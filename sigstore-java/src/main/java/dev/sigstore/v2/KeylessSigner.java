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
import dev.sigstore.encryption.Hashers;
import dev.sigstore.oidc.client.FakeOidcClient;
import dev.sigstore.oidc.client.OidcClients;
import dev.sigstore.oidc.client.OidcException;
import dev.sigstore.oidc.client.OidcToken;
import dev.sigstore.proto.rekor.v2.IdentityRequestV001;
import dev.sigstore.proto.rekor.v2.OidcCredential;
import dev.sigstore.rekor.client.RekorParseException;
import dev.sigstore.rekor.client.RekorVerificationException;
import dev.sigstore.trustroot.Service;
import dev.sigstore.v2.VerificationOptions.OidcTokenIdentity;
import dev.sigstore.v2.bundle.Bundle;
import dev.sigstore.v2.bundle.ImmutableBundle;
import dev.sigstore.v2.rekor.client.RekorClient;
import dev.sigstore.v2.rekor.client.RekorClientHttp;
import dev.sigstore.v2.rekor.client.RekorVerifier;
import dev.sigstore.v2.rekor.client.TLogProof;
import dev.sigstore.v2.rekor.client.WitnessPolicy;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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
    private URI rekorUrl;
    private Integer rekorVersion;
    private String logIdentity;
    private PublicKey logPublicKey;
    private WitnessPolicy witnessPolicy;
    private OidcClients oidcClients;

    @CanIgnoreReturnValue
    public Builder rekorUrl(URI rekorUrl, int version) {
      this.rekorUrl = rekorUrl;
      this.rekorVersion = version;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder rekorUrl(URI rekorUrl) {
      this.rekorUrl = rekorUrl;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder rekorVersion(int version) {
      this.rekorVersion = version;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder logIdentity(String logIdentity) {
      this.logIdentity = logIdentity;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder logPublicKey(PublicKey logPublicKey) {
      this.logPublicKey = logPublicKey;
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
    public KeylessSigner build() {
      Preconditions.checkNotNull(rekorUrl, "rekorUrl must be set");
      Preconditions.checkNotNull(rekorVersion, "rekorVersion must be set");
      Preconditions.checkNotNull(logIdentity, "logIdentity must be set");
      Preconditions.checkNotNull(logPublicKey, "logPublicKey must be set");
      Preconditions.checkNotNull(witnessPolicy, "witnessPolicy must be set");
      if (oidcClients == null) {
        oidcClients = FakeOidcClient.of();
      }
      var rekorService = Service.of(rekorUrl, rekorVersion);
      var rekorClient = RekorClientHttp.builder().setService(rekorService).build();
      var rekorVerifier = RekorVerifier.newRekorVerifier(logIdentity, logPublicKey, witnessPolicy);
      return new KeylessSigner(rekorClient, rekorVerifier, oidcClients);
    }

    @CanIgnoreReturnValue
    public Builder sigstorePublicDefaults()
        throws IOException,
            NoSuchAlgorithmException,
            InvalidKeySpecException,
            NoSuchProviderException {
      this.rekorUrl = URI.create("http://localhost:3006");
      this.rekorVersion = 3;

      String pemStr =
          java.nio.file.Files.readString(
              Paths.get("/Users/aaronlew/rekor-tiles/tests/testdata/pki/mldsa-pub-key.pem"));

      pemStr =
          pemStr
              .replace("-----BEGIN PUBLIC KEY-----", "")
              .replace("-----END PUBLIC KEY-----", "")
              .replaceAll("\\s", "");
      byte[] pubKeyBytes = Base64.getDecoder().decode(pemStr);

      X509EncodedKeySpec spec = new X509EncodedKeySpec(pubKeyBytes);

      Security.addProvider(new BouncyCastleProvider());
      PublicKey pubKey = KeyFactory.getInstance("ML-DSA", "BC").generatePublic(spec);

      Path policyPath =
          Paths.get("/Users/aaronlew/rekor-tiles/tests/testdata/witness/mldsa-policy.yaml");
      if (java.nio.file.Files.exists(policyPath)) {
        try {
          witnessPolicy(WitnessPolicy.from(java.nio.file.Files.readString(policyPath)));
        } catch (RekorParseException ignored) {
          this.witnessPolicy = WitnessPolicy.NONE;
        }
      } else {
        this.witnessPolicy = WitnessPolicy.NONE;
      }

      this.logIdentity = "rekor-local";
      this.logPublicKey = pubKey;
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
        var identity =
            OidcTokenIdentity.builder()
                .issuer(token.getIssuer())
                .subject(token.getSubjectAlternativeName())
                .build();
        byte[] leafHash = computeLeafHash(artifactDigest, identity);
        rekorVerifier.verifyProof(proof, leafHash);
      } catch (NoSuchAlgorithmException | RekorVerificationException ex) {
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

  private static byte[] computeLeafHash(byte[] artifactDigest, OidcTokenIdentity identity)
      throws NoSuchAlgorithmException {
    byte[] msgHash = MessageDigest.getInstance("SHA-256").digest(artifactDigest);
    byte[] rootHash =
        MessageDigest.getInstance("SHA-256")
            .digest(identity.getIssuer().getBytes(StandardCharsets.UTF_8));

    Map<String, String> claims = new HashMap<>();
    claims.put("identity", identity.getSubject());
    claims.put("issuer", identity.getIssuer());
    claims.put("subject", identity.getSubject());

    List<String> sortedKeys = new ArrayList<>(claims.keySet());
    Collections.sort(sortedKeys);
    ByteArrayOutputStream leafOs = new ByteArrayOutputStream();
    leafOs.write(0x01); // LeafVersionV1
    try {
      leafOs.write(rootHash);
      leafOs.write(msgHash);
      for (String key : sortedKeys) {
        String val = claims.get(key);
        byte[] kHash =
            MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8));
        byte[] vHash =
            MessageDigest.getInstance("SHA-256").digest(val.getBytes(StandardCharsets.UTF_8));
        byte[] kDoubleHash = MessageDigest.getInstance("SHA-256").digest(kHash);
        byte[] vDoubleHash = MessageDigest.getInstance("SHA-256").digest(vHash);
        leafOs.write(kDoubleHash);
        leafOs.write(vDoubleHash);
      }

      leafOs.write(new byte[32]); // receipt digest block (all zeros)
      ByteArrayOutputStream finalOs = new ByteArrayOutputStream();
      finalOs.write(0x00); // RFC6962 Leaf prefix
      finalOs.write(leafOs.toByteArray());
      return MessageDigest.getInstance("SHA-256").digest(finalOs.toByteArray());
    } catch (IOException e) {
      throw new RuntimeException(e); // ByteArrayOutputStream never throws IOException
    }
  }
}
