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
import dev.sigstore.TrustedRootProvider;
import dev.sigstore.common.json.JsonParseException;
import dev.sigstore.dsse.InTotoPayload;
import dev.sigstore.encryption.Hashers;
import dev.sigstore.rekor.client.RekorParseException;
import dev.sigstore.rekor.client.RekorVerificationException;
import dev.sigstore.trustroot.SigstoreConfigurationException;
import dev.sigstore.v2.bundle.Bundle;
import dev.sigstore.v2.rekor.client.RekorVerifier;
import dev.sigstore.v2.rekor.client.VerifierKey;
import dev.sigstore.v2.rekor.client.WitnessPolicy;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;

/** Verify TransparencyLogProofs from rekor signed using the PQC keyless signing flow. */
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

    private TrustedRootProvider trustedRootProvider;
    private WitnessPolicy witnessPolicy;

    @CanIgnoreReturnValue
    public Builder trustedRootProvider(TrustedRootProvider trustedRootProvider) {
      this.trustedRootProvider = trustedRootProvider;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder witnessPolicy(WitnessPolicy witnessPolicy) {
      this.witnessPolicy = witnessPolicy;
      return this;
    }

    @CheckReturnValue
    public KeylessVerifier build() throws SigstoreConfigurationException {
      Preconditions.checkNotNull(trustedRootProvider, "trustedRootProvider must be set");
      Preconditions.checkNotNull(witnessPolicy, "witnessPolicy must be set");
      var rekorVerifier =
          RekorVerifier.newRekorVerifier(
              VerifierKey.fromTrustedRoot(trustedRootProvider.get()), witnessPolicy);
      return new KeylessVerifier(rekorVerifier);
    }

    @CanIgnoreReturnValue
    public Builder sigstoreStagingDefaults() {
      trustedRootProvider = TrustedRootProvider.from(StagingTuf.clientBuilder());
      return this;
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
    var proof = bundle.getTransparencyLogProof();
    Map<String, String> claims;
    try {
      claims = proof.parseExtraData();
    } catch (RekorParseException ex) {
      throw new KeylessVerificationException(
          "Could not parse the extra data in the transparency log proof: " + ex.getMessage(), ex);
    }
    policy.checkClaims(claims);

    byte[] message = artifactDigest;
    if (bundle.getPayload().isPresent()) {
      var payload = bundle.getPayload().get();
      checkDssePayload(payload, artifactDigest);
      message = Hashers.from(HashAlgorithm.SHA2_256).hashBytes(payload.getPAE()).asBytes();
    }

    byte[] leafHash = IdentityLeaf.oidcLeafHash(message, policy.getIssuer(), claims);

    try {
      rekorVerifier.verifyProof(proof, leafHash);
    } catch (RekorVerificationException ex) {
      throw new KeylessVerificationException(
          "Transparency log inclusion proof could not be verified", ex);
    }
  }

  private static void checkDssePayload(Bundle.Payload payload, byte[] artifactDigest)
      throws KeylessVerificationException {
    if (!InTotoPayload.PAYLOAD_TYPE.equals(payload.getPayloadType())) {
      throw new KeylessVerificationException(
          "DSSE payload must have payload type "
              + InTotoPayload.PAYLOAD_TYPE
              + ", but found '"
              + payload.getPayloadType()
              + "'");
    }

    InTotoPayload inTotoPayload;
    try {
      inTotoPayload = InTotoPayload.from(new String(payload.getPayload(), StandardCharsets.UTF_8));
    } catch (JsonParseException jpe) {
      throw new KeylessVerificationException("Could not parse DSSE payload", jpe);
    }

    if (inTotoPayload.getSubject().stream()
        .noneMatch(subject -> matchesSha256(subject.getDigest().get("sha256"), artifactDigest))) {
      var providedHashes =
          inTotoPayload.getSubject().stream()
              .map(s -> s.getDigest().getOrDefault("sha256", "no-sha256-hash"))
              .collect(Collectors.joining(",", "[", "]"));
      throw new KeylessVerificationException(
          "Provided artifact digest does not match any subject sha256 digests in DSSE payload"
              + "\nprovided(hex) : "
              + Hex.toHexString(artifactDigest)
              + "\nverification  : "
              + providedHashes);
    }
  }

  private static boolean matchesSha256(String subjectDigestHex, byte[] artifactDigest) {
    if (subjectDigestHex == null) {
      return false;
    }
    try {
      return Arrays.equals(artifactDigest, Hex.decode(subjectDigestHex));
    } catch (DecoderException ex) {
      return false;
    }
  }
}
