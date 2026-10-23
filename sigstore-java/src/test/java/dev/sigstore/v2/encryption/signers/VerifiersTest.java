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
package dev.sigstore.v2.encryption.signers;

import dev.sigstore.UnsupportedAlgorithmException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class VerifiersTest {

  private static final byte[] CONTENT = "hello".getBytes(StandardCharsets.UTF_8);

  @BeforeAll
  public static void setUp() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void verify_mldsa44_withBcProvider() throws Exception {
    var kp = genKeyPairWithBcProvider("ML-DSA-44");
    var signature = genSignature(kp, "ML-DSA-44");
    var verifier = Verifiers.newVerifier(kp.getPublic());
    Assertions.assertTrue(verifier.verify(CONTENT, signature));
  }

  @Test
  public void verify_mldsa65_withBcProvider() throws Exception {
    var kp = genKeyPairWithBcProvider("ML-DSA-65");
    var signature = genSignature(kp, "ML-DSA-65");
    var verifier = Verifiers.newVerifier(kp.getPublic());
    Assertions.assertTrue(verifier.verify(CONTENT, signature));
  }

  @Test
  public void verify_mldsa87_withBcProvider() throws Exception {
    var kp = genKeyPairWithBcProvider("ML-DSA-87");
    var signature = genSignature(kp, "ML-DSA-87");
    var verifier = Verifiers.newVerifier(kp.getPublic());
    Assertions.assertTrue(verifier.verify(CONTENT, signature));
  }

  @Test
  public void verify_nonPqc_throwsUnsupported() throws Exception {
    var kpGen = KeyPairGenerator.getInstance("RSA");
    kpGen.initialize(2048);
    var kp = kpGen.generateKeyPair();
    Assertions.assertThrows(
        UnsupportedAlgorithmException.class, () -> Verifiers.newVerifier(kp.getPublic()));
  }

  private KeyPair genKeyPairWithBcProvider(String algorithm) throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "BC");
    return kpGen.generateKeyPair();
  }

  private byte[] genSignature(KeyPair kp, String algorithm) throws Exception {
    PrivateKey privateKey = kp.getPrivate();
    Signature sig = Signature.getInstance(algorithm, "BC");
    sig.initSign(privateKey);
    sig.update(CONTENT);
    return sig.sign();
  }
}
