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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.sigstore.UnsupportedAlgorithmException;
import java.security.KeyPairGenerator;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class AlgorithmRegistryTest {

  @BeforeAll
  public static void setUp() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void testGetSigningAlgorithm_ML_DSA_44() throws Exception {
    var keyPairGen = KeyPairGenerator.getInstance("ML-DSA-44", "BC");
    var publicKey = keyPairGen.generateKeyPair().getPublic();
    assertEquals(
        AlgorithmRegistry.SigningAlgorithm.ML_DSA_44,
        AlgorithmRegistry.getSigningAlgorithm(publicKey));
  }

  @Test
  public void testGetSigningAlgorithm_ML_DSA_65() throws Exception {
    var keyPairGen = KeyPairGenerator.getInstance("ML-DSA-65", "BC");
    var publicKey = keyPairGen.generateKeyPair().getPublic();
    assertEquals(
        AlgorithmRegistry.SigningAlgorithm.ML_DSA_65,
        AlgorithmRegistry.getSigningAlgorithm(publicKey));
  }

  @Test
  public void testGetSigningAlgorithm_ML_DSA_87() throws Exception {
    var keyPairGen = KeyPairGenerator.getInstance("ML-DSA-87", "BC");
    var publicKey = keyPairGen.generateKeyPair().getPublic();
    assertEquals(
        AlgorithmRegistry.SigningAlgorithm.ML_DSA_87,
        AlgorithmRegistry.getSigningAlgorithm(publicKey));
  }

  @Test
  public void testGetSigningAlgorithm_NonPqc_ThrowsUnsupported() throws Exception {
    var keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(2048);
    var publicKey = keyPairGen.generateKeyPair().getPublic();
    assertThrows(
        UnsupportedAlgorithmException.class,
        () -> AlgorithmRegistry.getSigningAlgorithm(publicKey));
  }
}
