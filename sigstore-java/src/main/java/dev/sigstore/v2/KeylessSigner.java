/*
 * Copyright 2026 The Sigstore Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dev.sigstore.v2;

import com.google.api.client.util.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.Files;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.CheckReturnValue;
import com.google.protobuf.ByteString;
import dev.sigstore.AlgorithmRegistry.HashAlgorithm;
import dev.sigstore.KeylessSignerException;
import dev.sigstore.SigningConfigProvider;
import dev.sigstore.TrustedRootProvider;
import dev.sigstore.encryption.Hashers;
import dev.sigstore.oidc.client.OidcClients;
import dev.sigstore.oidc.client.OidcException;
import dev.sigstore.oidc.client.OidcToken;
import dev.sigstore.proto.rekor.v2.IdentityRequestV001;
import dev.sigstore.proto.rekor.v2.OidcCredential;
import dev.sigstore.rekor.client.RekorParseException;
import dev.sigstore.rekor.client.RekorVerificationException;
import dev.sigstore.trustroot.Service;
import dev.sigstore.trustroot.SigstoreConfigurationException;
import dev.sigstore.v2.bundle.Bundle;
import dev.sigstore.v2.bundle.ImmutableBundle;
import dev.sigstore.v2.rekor.client.RekorClient;
import dev.sigstore.v2.rekor.client.RekorClientHttp;
import dev.sigstore.v2.rekor.client.RekorVerifier;
import dev.sigstore.v2.rekor.client.TLogProof;
import dev.sigstore.v2.rekor.client.VerifierKey;
import dev.sigstore.v2.rekor.client.WitnessPolicy;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Sign artifact digests using the PQC keyless signing flow and return a Bundle. */
public class KeylessSigner {

  private final RekorClient rekorClient;
  private final RekorVerifier rekorVerifier;
  private final OidcClients oidcClients;

  private KeylessSigner(
      RekorClient rekorClient, RekorVerifier rekorVerifier, OidcClients oidcClients) {
    this.rekorClient = rekorClient;
    this.rekorVerifier = rekorVerifier;
    this.oidcClients = oidcClients;
  }

  public static KeylessSigner.Builder builder() {
    return new KeylessSigner.Builder();
  }

  public static class Builder {
    private TrustedRootProvider trustedRootProvider;
    private SigningConfigProvider signingConfigProvider;
    private WitnessPolicy witnessPolicy;
    private OidcClients oidcClients;

    @CanIgnoreReturnValue
    public Builder trustedRootProvider(TrustedRootProvider trustedRootProvider) {
      this.trustedRootProvider = trustedRootProvider;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder signingConfigProvider(SigningConfigProvider signingConfigProvider) {
      this.signingConfigProvider = signingConfigProvider;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder witnessPolicy(WitnessPolicy witnessPolicy) {
      this.witnessPolicy = witnessPolicy;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder witnessPolicy(String witnessPolicyConfig) throws RekorParseException {
      this.witnessPolicy = WitnessPolicy.from(witnessPolicyConfig);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder oidcClients(OidcClients oidcClients) {
      this.oidcClients = oidcClients;
      return this;
    }

    @CheckReturnValue
    public KeylessSigner build() throws SigstoreConfigurationException {
      Preconditions.checkNotNull(trustedRootProvider, "trustedRootProvider must be set");
      Preconditions.checkNotNull(signingConfigProvider, "signingConfigProvider must be set");
      Preconditions.checkNotNull(witnessPolicy, "witnessPolicy must be set");
      var trustedRoot = trustedRootProvider.get();
      var signingConfig = signingConfigProvider.get();

      var rekorService = Service.select(signingConfig.getTLogs(), List.of(2));
      if (rekorService.isEmpty()) {
        throw new SigstoreConfigurationException(
            "No suitable rekor target was found in signing config");
      }

      if (oidcClients == null) {
        var oidcService = Service.select(signingConfig.getOidcProviders(), List.of(1));
        if (oidcService.isEmpty()) {
          throw new SigstoreConfigurationException(
              "No suitable oidc target was found in signing config");
        }
        oidcClients = OidcClients.from(oidcService.get());
      }

      var rekorClient = RekorClientHttp.builder().setService(rekorService.get()).build();
      var rekorVerifier =
          RekorVerifier.newRekorVerifier(VerifierKey.fromTrustedRoot(trustedRoot), witnessPolicy);
      return new KeylessSigner(rekorClient, rekorVerifier, oidcClients);
    }

    @CanIgnoreReturnValue
    public Builder sigstoreStagingDefaults() {
      var tufClientBuilder = StagingTuf.clientBuilder();
      trustedRootProvider = TrustedRootProvider.from(tufClientBuilder);
      signingConfigProvider = SigningConfigProvider.from(tufClientBuilder);
      witnessPolicy = WitnessPolicy.NONE;
      return this;
    }
  }

  /**
   * Sign one or more artifact digests using the keyless PQC signing workflow.
   *
   * @param artifactDigests sha256 digests of the artifacts to sign.
   * @return a list of PQC sigstore bundles.
   */
  @CheckReturnValue
  public List<Bundle> sign(List<byte[]> artifactDigests) throws KeylessSignerException {
    if (artifactDigests.isEmpty()) {
      throw new IllegalArgumentException("Require one or more digests");
    }

    for (var digest : artifactDigests) {
      if (digest.length != 32) {
        throw new KeylessSignerException(
            "Invalid digest length: " + digest.length + " for PQC signing (expected SHA-256)");
      }
    }

    OidcToken token;
    try {
      token = oidcClients.getIDToken();
    } catch (OidcException ex) {
      throw new KeylessSignerException("Failed to obtain OIDC token", ex);
    }

    var result = ImmutableList.<Bundle>builder();

    for (var artifactDigest : artifactDigests) {
      var oidc = OidcCredential.newBuilder().setToken(token.getIdToken()).build();
      var message = ByteString.copyFrom(artifactDigest);
      var req = IdentityRequestV001.newBuilder().setOidc(oidc).setMessage(message).build();

      TLogProof proof;
      try {
        proof = rekorClient.putEntry(req);
      } catch (IOException | RekorParseException ex) {
        throw new KeylessSignerException("Failed to put entry in rekor", ex);
      }

      try {
        var claims = proof.parseExtraData();
        var issuer = claims.get("issuer");
        if (issuer == null || !claims.containsKey("identity")) {
          throw new KeylessSignerException(
              "tlog proof must have \"issuer\" and \"identity\" claims");
        }
        byte[] leafHash = IdentityLeaf.oidcLeafHash(artifactDigest, issuer, claims);
        rekorVerifier.verifyProof(proof, leafHash);
      } catch (RekorParseException | RekorVerificationException ex) {
        throw new KeylessSignerException("Failed to validate rekor entry after signing", ex);
      }

      var bundle = ImmutableBundle.builder().tlogProof(proof).build();
      result.add(bundle);
    }

    return result.build();
  }

  /**
   * Convenience wrapper around {@link #sign(List)} to sign a single digest.
   *
   * @param artifactDigest sha256 digest of the artifact to sign.
   * @return a PQC sigstore bundle.
   */
  @CheckReturnValue
  public Bundle sign(byte[] artifactDigest) throws KeylessSignerException {
    return sign(List.of(artifactDigest)).get(0);
  }

  /**
   * Convenience wrapper around {@link #sign(List)} to accept files instead of digests.
   *
   * @param artifacts list of the artifacts to sign.
   * @return a map of artifacts and their PQC sigstore bundles.
   */
  @CheckReturnValue
  public Map<Path, Bundle> signFiles(List<Path> artifacts) throws KeylessSignerException {
    if (artifacts.isEmpty()) {
      throw new IllegalArgumentException("Require one or more paths");
    }
    var digests = new ArrayList<byte[]>(artifacts.size());
    for (var artifact : artifacts) {
      var artifactByteSource = Files.asByteSource(artifact.toFile());
      var hashFunction = Hashers.from(HashAlgorithm.SHA2_256);
      try {
        digests.add(artifactByteSource.hash(hashFunction).asBytes());
      } catch (IOException ex) {
        throw new KeylessSignerException("Failed to hash artifact " + artifact, ex);
      }
    }
    var signingResult = sign(digests);
    var result = ImmutableMap.<Path, Bundle>builder();
    for (int i = 0; i < artifacts.size(); i++) {
      result.put(artifacts.get(i), signingResult.get(i));
    }
    return result.build();
  }

  /**
   * Convenience wrapper around {@link #sign(List)} to accept a single file.
   *
   * @param artifact the artifact to sign.
   * @return a PQC sigstore bundle.
   */
  @CheckReturnValue
  public Bundle signFile(Path artifact) throws KeylessSignerException {
    return signFiles(List.of(artifact)).get(artifact);
  }
}
