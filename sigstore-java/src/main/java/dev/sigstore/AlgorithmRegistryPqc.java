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
package dev.sigstore;

import java.security.PublicKey;
import java.util.Locale;
import org.bouncycastle.jcajce.interfaces.MLDSAKey;

public class AlgorithmRegistryPqc {

  /**
   * Determine the post-quantum signing algorithm based on the public key.
   *
   * @param publicKey the public key
   * @return the signing algorithm
   * @throws UnsupportedAlgorithmException if the key algorithm or curve is not supported
   */
  public static SigningAlgorithm getSigningAlgorithm(PublicKey publicKey)
      throws UnsupportedAlgorithmException {
    String algorithm = publicKey.getAlgorithm();
    if (algorithm != null
        && (algorithm.startsWith("ML-DSA")
            || algorithm.startsWith("MLDSA")
            || algorithm.startsWith("Dilithium"))) {
      String algUpper = algorithm.toUpperCase(Locale.ROOT);
      if (algUpper.contains("44") || algUpper.contains("DILITHIUM2")) {
        return SigningAlgorithm.ML_DSA_44;
      }
      if (algUpper.contains("65") || algUpper.contains("DILITHIUM3")) {
        return SigningAlgorithm.ML_DSA_65;
      }
      if (algUpper.contains("87") || algUpper.contains("DILITHIUM5")) {
        return SigningAlgorithm.ML_DSA_87;
      }
      if (publicKey instanceof MLDSAKey) {
        var mldsaKey = (MLDSAKey) publicKey;
        if (mldsaKey.getParameterSpec() != null && mldsaKey.getParameterSpec().getName() != null) {
          String specName = mldsaKey.getParameterSpec().getName().toLowerCase(Locale.ROOT);
          if (specName.contains("44")) {
            return SigningAlgorithm.ML_DSA_44;
          }
          if (specName.contains("65")) {
            return SigningAlgorithm.ML_DSA_65;
          }
          if (specName.contains("87")) {
            return SigningAlgorithm.ML_DSA_87;
          }
        }
      }
      throw new UnsupportedAlgorithmException(
          "Unsupported ML-DSA parameter set for algorithm: " + algorithm);
    }
    throw new UnsupportedAlgorithmException("Unsupported PQC key algorithm: " + algorithm);
  }

  public enum SigningAlgorithm {
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87;
  }
}
