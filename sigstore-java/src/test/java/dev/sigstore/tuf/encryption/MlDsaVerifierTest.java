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
package dev.sigstore.tuf.encryption;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class MlDsaVerifierTest {

  private static final byte[] CONTENT = "abcdef".getBytes(StandardCharsets.UTF_8);

  @Test
  public void testVerify_MlDsa() throws Exception {
    Security.addProvider(new BouncyCastleProvider());

    var keyPair = genKeyPair();
    var signature = genSignature(keyPair);
    var verifier = new MlDsaVerifier(keyPair.getPublic());
    Assertions.assertTrue(verifier.verify(CONTENT, signature));
  }

  private KeyPair genKeyPair() throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ML-DSA-44", "BC");
    return kpGen.generateKeyPair();
  }

  private byte[] genSignature(KeyPair keyPair) throws Exception {
    Signature signature = Signature.getInstance("ML-DSA", "BC");
    signature.initSign(keyPair.getPrivate());
    signature.update(new byte[] {0x74, 0x75, 0x66, 0x01});
    signature.update(MessageDigest.getInstance("SHA-512").digest(CONTENT));
    return signature.sign();
  }
}
