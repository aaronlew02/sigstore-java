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
  private static final String WITNESS_POLICY =
      "witness tf-mldsa44 staging.witness.transparency.goog/ring-any-bells+5774b075+Bi1GzCU2/5mxwhCBcfEpKliaoIg171qCFP3r3svllk/XlYj7hzNl9yVqfL2EBUdbC1vbnyCF6gD5XOFjsK4n64/mKMFIsWnuwoCVpqfUvHiM3sf48LMvFvWkQhHGEizw7FLiX+nmyM/EhzoNJ+98AKfLOjTvOFCqnb0RC9lLI+MlWGalc4fgNXYwcSBmShYfMBcaZzUt77SOHXORybbdeaGtRBU93KvBl03A9zipY5Hmn1E18ZtWtflwSV/tqgWs1Od1Hs+jHMGigKHKDaE4zYdRwkHFdf8VsTx4LJv2Ok0/4dfLxAZDEXAhpAbCbluBW5cf2Q6owZRa9obSEbjYXKCzSYySNh01rRf6K9o0VeFEK/6+CM45GvD/pMu++J1xGInxAjCoNqK3j3Rmx93WpIRmiwUhL+if1rPzrZO2m3Skek8QQx0Ke+HiaGcRYPUHqQ3Y/zJrJyXapg9lx9CgVXfOUWO89bocspztYABz43m5jqGaltjgOGUtYeoNvbtzzkJOugLLH43PwNPll064+oG4kmCAdVVS2VZHTm20l5qZ7jBumsrauD/S6dBpmZzua0hJlxf94I9gd8zmLsKLvjc9IAKkY26rMuAzl6Hu9NfXMM+8ZAtuJ6q2EKxy47dDn01AjrjZ/qYXiJbXDFTcHlUWF3fCujYgo8nCcoDYFbjby99TL++sHmivsz5kO2cR6xeJphlGt4Di5qxUaf9K70keUqr22R1rcLyGU5dPzWE0cAp+Z6dmvq4rM6QsTLfOjvZlydj/zfRs6BOBzlPEoqEWCN+A2MPCTm6NBV7L/24z0fUoGBh/08BGY37FU3nWwuldLKC+9nr1ItMhOKWKx8pkHnSllJEY0XVxpzE3eV08sCQyuRdVi++2K8Xnb3nUA7uQBr90IBCWzPzY/NWaBhVwqr+S1XzxHcHogWbVfdDxYgmj1tGWQaampa1ZwIBfjlHfn3ji2wSG8Mzd3jGTIX/4TlhN/rAlscnqnABEo24mzrQpOz7Dhc8hKhvAOXvS9b6GN6dml+O68UQg/qXNqBQep8UxOtmxmTMs5t/wBDNzkYwWONKwf682AaZfKaAOurHpkuGHlgCAtylWY/o4PDCyZ3e7wQfNRZK6asOUaq1CthaxRrLcemyvZYcydvw2ZFH/SF8J1RoeXtFRy4adRjPqNrzNk0um/cvxX8QB1Qf00sHXLOY7IfYdl6xUnsMsGrE5XkXWKxl8eN+VJhMpONQgB9MqgxLcQquesFpfeeo8k3MsX4+weJ8il/UNq7r6JWc+5/0E9bFDUTp30tSiwCEPEXBlQR8LbbBSTU7/cRru62D8L0/QvVnT4stFDouJpNPP5V7BbqPC36hQi7yVPXRyCUzsroDquICtaKqqnk90Ej0smXodBBXm4BHodXT1eXND5jR8N1AqzZcpucSmA6G5b33oXL3dlX+GP3q4JslJHRlQWFvp8Qbv6GYbnYGnvv4tIGxslibfdx1mKzuXczNeYlrlWJrddIXrFKgiwFBFTXG0HlIgeAMlF99g9Efyd4g/aJpmNLa8Qx7PV3+SZE3nrum37tyVVKfK9q7eXDYztOgIOKFNb3iS2CXCjrf3CsKGbXX+PvjqfBAH1cTc/lrDb2Rg2beH5mQam4zTPv2ndkPjEC0c5q92y+VNzBlKSnnBNlRg5fKIwbH3s8lOP51mdCYAdpwd8M6rYxs/jy37jWb9Utmh80HA3yR8KBDZYxEKkghO0PAFaC5kQIjUeYs= https://staging.witness.transparency.goog/ring-any-bells\n"
          + "quorum tf-mldsa44\n";

  private static String proofText;
  private static List<VerifierKey> logKeys;

  @BeforeAll
  public static void loadResources() throws Exception {
    proofText =
        Resources.toString(
            Resources.getResource("dev/sigstore/v2/samples/rekor-response/valid/tlog-proof.txt"),
            StandardCharsets.UTF_8);
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
    var verifier = RekorVerifier.newRekorVerifier(logKeys, WITNESS_POLICY);
    verifier.verifyProof(proof, leafHash(proof, DIGEST));
  }

  @Test
  public void verifyProof_witnessPolicyNotSatisfied() throws Exception {
    var proof = parse(withoutSignature(proofText, WITNESS_NAME));
    var verifier = RekorVerifier.newRekorVerifier(logKeys, WITNESS_POLICY);
    var leafHash = leafHash(proof, DIGEST);
    var ex =
        Assertions.assertThrows(
            RekorVerificationException.class, () -> verifier.verifyProof(proof, leafHash));
    Assertions.assertEquals(
        "Witness policy not satisfied. Verified witnesses: []", ex.getMessage());
  }

  private static TLogProof parse(String text) {
    return TLogProof.parse(text.getBytes(StandardCharsets.UTF_8));
  }

  private static byte[] leafHash(TLogProof proof, byte[] digest) throws Exception {
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
