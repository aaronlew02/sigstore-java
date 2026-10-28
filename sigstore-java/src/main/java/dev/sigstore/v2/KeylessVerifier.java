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
import com.google.common.io.Files;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.CheckReturnValue;
import dev.sigstore.AlgorithmRegistry.HashAlgorithm;
import dev.sigstore.KeylessVerificationException;
import dev.sigstore.encryption.Hashers;
import dev.sigstore.rekor.client.RekorParseException;
import dev.sigstore.rekor.client.RekorVerificationException;
import dev.sigstore.v2.bundle.Bundle;
import dev.sigstore.v2.rekor.client.RekorVerifier;
import dev.sigstore.v2.rekor.client.WitnessPolicy;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** Verify TLogProofs from rekor signed using the PQC keyless signing flow. */
public class KeylessVerifier {

  private final RekorVerifier rekorVerifier;

  private KeylessVerifier(RekorVerifier rekorVerifier) {
    this.rekorVerifier = rekorVerifier;
  }

  @CheckReturnValue
  public static KeylessVerifier.Builder builder() {
    return new KeylessVerifier.Builder();
  }

  public static class Builder {

    private String logIdentity;
    private PublicKey logPublicKey;
    private WitnessPolicy witnessPolicy;

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

    @CheckReturnValue
    public KeylessVerifier build() {
      Preconditions.checkNotNull(logIdentity, "logIdentity must be set");
      Preconditions.checkNotNull(logPublicKey, "logPublicKey must be set");
      Preconditions.checkNotNull(witnessPolicy, "witnessPolicy must be set");
      var rekorVerifier = RekorVerifier.newRekorVerifier(logIdentity, logPublicKey, witnessPolicy);
      return new KeylessVerifier(rekorVerifier);
    }

    @CanIgnoreReturnValue
    public Builder sigstorePublicDefaults()
        throws IOException,
            NoSuchAlgorithmException,
            InvalidKeySpecException,
            NoSuchProviderException {
      // Load local ML-DSA Public Key from rekor-tiles
      String pemStr =
          java.nio.file.Files.readString(
              Paths.get("/Users/aaronlew/rekor-tiles/tests/testdata/pki/mldsa-pub-key.pem"));

      // Strip PEM headers
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

      return logIdentity("rekor-local").logPublicKey(pubKey);
    }
  }

  /** Convenience wrapper around {@link #verify(byte[], Bundle, VerificationOptions)}. */
  public void verify(Path artifact, Bundle bundle, VerificationOptions options)
      throws KeylessVerificationException {
    try {
      var artifactDigest =
          Files.asByteSource(artifact.toFile())
              .hash(Hashers.from(HashAlgorithm.SHA2_256))
              .asBytes();
      verify(artifactDigest, bundle, options);
    } catch (IOException ex) {
      throw new KeylessVerificationException("Could not hash artifact: " + artifact, ex);
    }
  }

  /**
   * Verify that the inputs can attest to the validity of a PQC signature using sigstore's keyless
   * infrastructure. If no exception is thrown, it should be assumed verification has passed.
   *
   * @param artifactDigest the digest of the artifact that is being verified
   * @param bundle the PQC sigstore signature bundle to verify
   * @param options the keyless verification data and options
   * @throws KeylessVerificationException if the signing information could not be verified
   */
  public void verify(byte[] artifactDigest, Bundle bundle, VerificationOptions options)
      throws KeylessVerificationException {
    var policy = options.getIdentityPolicy();
    var proof = bundle.getTlogProof();
    Map<String, String> claims;
    try {
      claims = proof.parseExtraData();
    } catch (RekorParseException ex) {
      throw new KeylessVerificationException(
          "Could not parse the extra data in the tlog proof: " + ex.getMessage(), ex);
    }
    policy.checkClaims(claims);
    byte[] leafHash = IdentityLeaf.oidcLeafHash(artifactDigest, policy.getIssuer(), claims);
    try {
      rekorVerifier.verifyProof(proof, leafHash);
    } catch (RekorVerificationException ex) {
      throw new KeylessVerificationException(
          "Transparency log inclusion proof could not be verified", ex);
    }
  }
}
