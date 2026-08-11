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

import dev.sigstore.rekor.client.RekorParseException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class WitnessPolicyTest {

  private static final String MLDSA_TEST_POLICY =
      "witness o1 rekor-witness-test+0a24f7bd+BtJXRyNcK7dzPDBCZMsHgTG8O/g+yGm3jaWYzwzVQ9cuRzfZY5y1XnZM0D8IYXxYuNqhdGk6FcSIB2yBGajESPSnpFoE0lNltyIODwfXwVNjGhrqNW/p+xvuCkhmWZm6HAPvp9N+woZ2Mk1pnvm9Lhz7U1VBTZ7uA1+wqnDkVoL16bBpN3Na3ocsoDTUsw+NNBQk41DZHcnAfEqas0EAFOL+bo1F6NFdYTYkFtFuPDqyKlXtAfRX/qJxjdGvgoyhS941VFHDZK74OxLo3hYMieOImkj/QiwQ3sY2ufr4C3vEsHBiIZPn37X252ZY+xQXNS7x0xRowHInxla+Jtgg0IRSJHT3EGRtbADnX+jajakztXbLs1dhVbOzHgMI11BB3NVdv/KENQcY2Ssqlm70ra/h8foMNCl3loWXblOqwaKPzChZFIqo3L+Oy0CL0Yg6MT4Ge4pi6+8RJcdBQupmHtaAY1gCPodwqdWBuetcpmhaxJcpzMz5JyI8y6V6iRHOywOUTy1n8Rp4t32sX6s+mVEtXrI4AXXQtxj0DCr7YvbFHb2hYeLkVB+85lmHvMOvIYqjrTZsabOFqYZA3oG/t03RcZgrJir6zlT7WguiHMlFwR8hL2LMZrxv+AIIYwsgDCw4YybhhgKbOUgzs6gKwaM+FLEiGDwLYNxvIvSaUI6wa3s3aNQGZiNYO/8w7D1SU17i2P3NIoV3ZNM9vbvy2mCOAqBpzmSs7vPRuU9cpwjWavG9mir0342X8x+briBPKGU7BY3kZ2kTKSC/7Lj7UE1zVXsfBKDnwCmd1Hohugx8K2y307jGcdRipVNB/ruKWK40yXq/a/baillaGP/R8POdPmnUE7hSRbpqS6EnNxYmbhXQ0M/WB9hrEgt6nhUzBjXIiivmplLFbL45/2fK3Y5MqI7xjvSsN0V1DQGvbQcVh4Btb8w9AT/uQ1qsN4TynaxF/AVY6RV1jRQCygLt98dPxF/JClN4bUpaO0jefIgjgg3ZFA2g8Qb8K8KvZmLmkNzhkf+C3iiiZIr37vIpUeGBocTfCuSiXIIBsWEPYUWl/I3631c1utU7ktNUQMzkHgjQIUQcwEAQLIMiwhWdEtsPUBShntYVsxW52qtPGDdnm7jTT+Wyoiq6Gxd/q1r6RipudSRF0VDvMIB7fvSQ2fb0cwf6u40FbRNUf54Kr4uJp5OZHOVOUQruNDYDVxb/ORZJ1JV341WHf7yjpM0b8wQ+utf+tkG1aA+MJY4qDa1lVLQMVowybTXow+DeHhtpBWDFkmX3NYBY+rtwQYe2OdRwYuWTaMdtgkAkGnygvHrDeY4LUI1bmouv8Im4k+3w68q/QZeMUPb8UuIkkf58uAb+YMIem3PW2QuwScGz9yEUCkfrJB9QGSm4F6ENyj5iig1+y0xhu91UzTOnOSxCOe7rJhjKD2PkqjNnC7a28PLp4dOr069sRyQYk6O64WIWbVek8ClF1vx1JHxrIZgdj86qsOBIPC+O9q+p+yE+Z/cAO2LC0clYKMNS+jMpYal6wnGZQrMjNky3Tr3PyxvZSimu1J5wDRWLCyK7qBUYefaVyibbgVJng5/CNHWtJnhhX1zrWLsBDYkO+VNlM4BX0DOQmDVddNLS0IGequhrYjHof9mfTp0Bj5QnnKn9rHKH0CW/vjYR58t7vVeSCaIXFm9syz+LZLAvtITr50xob71w4a+HdL5Y6grbnlx6ZNOZotIw8r6NYZabhXHNsOm7dfY= http://witness:8100\n"
          + "quorum o1\n";

  @BeforeAll
  public static void setup() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void testDefaultNonePolicy() {
    WitnessPolicy policy = WitnessPolicy.NONE;
    Assertions.assertTrue(policy.isSatisfied(Set.of()));
    Assertions.assertTrue(policy.isSatisfied(Set.of("any-witness")));
    Assertions.assertTrue(policy.getWitnessPublicKeys().isEmpty());
  }

  @Test
  public void testParseQuorumNone() throws Exception {
    String config = "# Policy with no required witness\n" + "quorum none\n";
    WitnessPolicy policy = WitnessPolicy.from(config);
    Assertions.assertTrue(policy.isSatisfied(Set.of()));
    Assertions.assertTrue(policy.isSatisfied(Set.of("w1")));
    Assertions.assertTrue(policy.getWitnessPublicKeys().isEmpty());
  }

  @Test
  public void testParseMldsaPolicy() throws Exception {
    WitnessPolicy policy = WitnessPolicy.from(MLDSA_TEST_POLICY);

    Map<String, PublicKey> keys = policy.getWitnessPublicKeys();
    Assertions.assertNotNull(keys.get("rekor-witness-test"));
    Assertions.assertNotNull(keys.get("o1"));
    Assertions.assertTrue(keys.get("rekor-witness-test").getAlgorithm().startsWith("ML-DSA"));

    Assertions.assertFalse(policy.isSatisfied(Set.of()));
    Assertions.assertFalse(policy.isSatisfied(Set.of("other-witness")));
    Assertions.assertTrue(policy.isSatisfied(Set.of("rekor-witness-test")));
    Assertions.assertTrue(policy.isSatisfied(Set.of("o1")));
  }

  @Test
  public void testParseComplexGroupsAndQuorum() throws Exception {
    // Generate dummy ML-DSA keys
    var kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
    var kp1 = kpg.generateKeyPair();
    var kp2 = kpg.generateKeyPair();
    var kp3 = kpg.generateKeyPair();

    String b64Spki1 = Base64.getEncoder().encodeToString(kp1.getPublic().getEncoded());
    String b64Spki2 = Base64.getEncoder().encodeToString(kp2.getPublic().getEncoded());
    String b64Spki3 = Base64.getEncoder().encodeToString(kp3.getPublic().getEncoded());

    String policyStr =
        "witness w1 "
            + b64Spki1
            + "\n"
            + "witness w2 "
            + b64Spki2
            + "\n"
            + "witness w3 "
            + b64Spki3
            + "\n"
            + "group g_all all w1 w2\n"
            + "group g_any any w2 w3\n"
            + "group g_root 2 g_all g_any w3\n"
            + "quorum g_root\n";

    WitnessPolicy policy = WitnessPolicy.from(policyStr);
    Assertions.assertEquals(3, policy.getWitnessPublicKeys().size());

    // Only w1 verified: g_all (0/2, false), g_any (0/1, false), w3 (false) -> total satisfied = 0 <
    // 2
    Assertions.assertFalse(policy.isSatisfied(Set.of("w1")));

    // w1 and w2 verified: g_all (2/2, true), g_any (1/1, true), w3 (false) -> total satisfied = 2
    // >= 2 -> true
    Assertions.assertTrue(policy.isSatisfied(Set.of("w1", "w2")));

    // w2 and w3 verified: g_all (1/2, false), g_any (2/1, true), w3 (true) -> total satisfied = 2
    // >= 2 -> true
    Assertions.assertTrue(policy.isSatisfied(Set.of("w2", "w3")));

    // Only w3 verified: g_all (0/2, false), g_any (1/1, true), w3 (true) -> total satisfied = 2 >=
    // 2 -> true
    Assertions.assertTrue(policy.isSatisfied(Set.of("w3")));
  }

  @Test
  public void testParseErrors() throws Exception {
    // Empty config
    Assertions.assertThrows(RekorParseException.class, () -> WitnessPolicy.from(""));
    Assertions.assertThrows(
        RekorParseException.class, () -> WitnessPolicy.from("   \n# comment\n"));

    // Missing quorum
    var kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
    var mldsaKp = kpg.generateKeyPair();
    String mldsaB64 = Base64.getEncoder().encodeToString(mldsaKp.getPublic().getEncoded());
    Assertions.assertThrows(
        RekorParseException.class, () -> WitnessPolicy.from("witness w1 " + mldsaB64));

    // Rejection of non-PQC keys (Ed25519)
    var ed25519Kp = KeyPairGenerator.getInstance("Ed25519", "BC").generateKeyPair();
    String ed25519B64 = Base64.getEncoder().encodeToString(ed25519Kp.getPublic().getEncoded());
    Assertions.assertThrows(
        RekorParseException.class,
        () -> WitnessPolicy.from("witness w1 " + ed25519B64 + "\nquorum w1\n"));

    // Undefined member in group
    Assertions.assertThrows(
        RekorParseException.class,
        () -> WitnessPolicy.from("group g1 all w_undefined\nquorum g1\n"));

    // Duplicate symbol name
    Assertions.assertThrows(
        RekorParseException.class,
        () ->
            WitnessPolicy.from(
                "witness w1 " + mldsaB64 + "\n" + "witness w1 " + mldsaB64 + "\n" + "quorum w1\n"));

    // Group threshold out of bounds
    Assertions.assertThrows(
        RekorParseException.class,
        () ->
            WitnessPolicy.from(
                "witness w1 " + mldsaB64 + "\n" + "group g1 2 w1\n" + "quorum g1\n"));
  }

  @Test
  public void testFromPathAndInputStream(@TempDir Path tempDir) throws Exception {
    var kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
    var kp = kpg.generateKeyPair();
    String b64Spki = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
    String policyStr = "witness w1 " + b64Spki + "\nquorum w1\n";

    Path policyFile = tempDir.resolve("witness-policy.conf");
    Files.writeString(policyFile, policyStr);

    WitnessPolicy fromPath = WitnessPolicy.from(policyFile);
    Assertions.assertTrue(fromPath.isSatisfied(Set.of("w1")));
    Assertions.assertEquals(1, fromPath.getWitnessPublicKeys().size());

    try (InputStream is = Files.newInputStream(policyFile)) {
      WitnessPolicy fromIs = WitnessPolicy.from(is);
      Assertions.assertTrue(fromIs.isSatisfied(Set.of("w1")));
      Assertions.assertEquals(1, fromIs.getWitnessPublicKeys().size());
    }
  }
}
