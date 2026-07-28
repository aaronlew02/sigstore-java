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
package dev.sigstore.v2.rekor.client;

import com.google.common.io.Resources;
import dev.sigstore.rekor.client.RekorVerificationException;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import dev.sigstore.v2.IdentityLeaf;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class RekorVerifierTest {

  private static final byte[] DIGEST =
      Hex.decode("8be1ee6c45bf20e3980f42d332ded574d3d1c91288b506e1309fd351fe74e064");
  private static final String ISSUER = "https://accounts.google.com";
  private static final String LOG_NAME = "pqc27-a1.us-east4.rekor.sigstage.dev";
  private static final String WITNESS_NAME = "staging.witness.transparency.goog/ring-any-bells";

  private static String proofText;
  private static WitnessPolicy witnessPolicy;
  private static List<VerifierKey> logKeys;

  @BeforeAll
  public static void loadResources() throws Exception {
    proofText =
        Resources.toString(
            Resources.getResource("dev/sigstore/v2/samples/rekor-response/valid/tlog-proof.txt"),
            StandardCharsets.UTF_8);
    witnessPolicy =
        WitnessPolicy.from(
            Resources.toString(
                Resources.getResource("dev/sigstore/v2/trustroot/staging_witness_policy.txt"),
                StandardCharsets.UTF_8));
    try (var is =
        Resources.getResource("dev/sigstore/v2/trustroot/staging_trusted_root.json").openStream()) {
      logKeys = VerifierKey.fromTrustedRoot(SigstoreTrustedRoot.from(is));
    }
  }

  @Test
  public void verifyProof() throws Exception {
    var proof = parse(proofText);
    var verifier = RekorVerifier.newRekorVerifier(logKeys, WitnessPolicy.NONE);
    verifier.verifyProof(proof, leafHash(proof, DIGEST));
  }

  @Test
  public void verifyProof_wrongLeafHash() throws Exception {
    var proof = parse(proofText);
    var verifier = RekorVerifier.newRekorVerifier(logKeys, WitnessPolicy.NONE);
    var leafHash = leafHash(proof, new byte[32]);
    var ex =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyProof(proof, leafHash));
    Assertions.assertEquals("Inclusion proof verification failed", ex.getMessage());
  }

  @Test
  public void verifyProof_invalidLogSignature() throws Exception {
    var proof = parse(withChangedSignature(proofText, LOG_NAME));
    var verifier = RekorVerifier.newRekorVerifier(logKeys, WitnessPolicy.NONE);
    var leafHash = leafHash(proof, DIGEST);
    var ex =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyProof(proof, leafHash));
    Assertions.assertEquals(
        "Could not verify checkpoint signature for identity: " + LOG_NAME, ex.getMessage());
  }

  @Test
  public void verifyProof_untrustedOrigin() throws Exception {
    var proof = parse(proofText);
    var otherLogKeys =
        List.<VerifierKey>of(
            ImmutableVerifierKey.builder().from(logKeys.get(0)).name("other.example.com").build());
    var verifier = RekorVerifier.newRekorVerifier(otherLogKeys, WitnessPolicy.NONE);
    var leafHash = leafHash(proof, DIGEST);
    var ex =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyProof(proof, leafHash));
    Assertions.assertEquals("Checkpoint origin is not a trusted log: " + LOG_NAME, ex.getMessage());
  }

  @Test
  public void verifyProof_witnessPolicySatisfied() throws Exception {
    var proof = parse(proofText);
    var verifier = RekorVerifier.newRekorVerifier(logKeys, witnessPolicy);
    verifier.verifyProof(proof, leafHash(proof, DIGEST));
  }

  @Test
  public void verifyProof_witnessPolicyNotSatisfied() throws Exception {
    var proof = parse(withoutSignature(proofText, WITNESS_NAME));
    var verifier = RekorVerifier.newRekorVerifier(logKeys, witnessPolicy);
    var leafHash = leafHash(proof, DIGEST);
    var ex =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyProof(proof, leafHash));
    Assertions.assertTrue(
        ex.getMessage().startsWith("Witness policy not satisfied. Verified witnesses: "),
        ex.getMessage());
  }

  @Test
  public void verifyProof_invalidWitnessCosignature() throws Exception {
    var proof = parse(withChangedSignature(proofText, WITNESS_NAME));
    var verifier = RekorVerifier.newRekorVerifier(logKeys, witnessPolicy);
    var leafHash = leafHash(proof, DIGEST);
    var ex =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyProof(proof, leafHash));
    Assertions.assertEquals(
        "Could not verify checkpoint signature for identity: " + WITNESS_NAME, ex.getMessage());
  }

  private static TransparencyLogProof parse(String text) {
    return TransparencyLogProof.parse(text.getBytes(StandardCharsets.UTF_8));
  }

  private static byte[] leafHash(TransparencyLogProof proof, byte[] digest) throws Exception {
    return IdentityLeaf.oidcLeafHash(digest, ISSUER, proof.parseExtraData());
  }

  private static String withChangedSignature(String text, String name) {
    var matcher = Pattern.compile("(?m)^\u2014 " + Pattern.quote(name) + " (\\S+)$").matcher(text);
    Assertions.assertTrue(matcher.find());
    byte[] signature = Base64.getDecoder().decode(matcher.group(1));
    signature[100] ^= 1;
    return text.substring(0, matcher.start(1))
        + Base64.getEncoder().encodeToString(signature)
        + text.substring(matcher.end(1));
  }

  private static String withoutSignature(String text, String name) {
    return text.replaceAll("(?m)^\u2014 " + Pattern.quote(name) + " \\S+\n", "");
  }
}
