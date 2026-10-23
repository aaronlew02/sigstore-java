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
import dev.sigstore.encryption.signers.Verifier;
import java.security.PublicKey;
import org.bouncycastle.jcajce.interfaces.MLDSAKey;

public class Verifiers {

  /** Returns a new verifier for the provided post-quantum public key. */
  public static Verifier newVerifier(PublicKey publicKey) throws UnsupportedAlgorithmException {
    String algorithm = publicKey.getAlgorithm();
    if (algorithm != null
        && (algorithm.startsWith("ML-DSA")
            || algorithm.startsWith("MLDSA")
            || algorithm.startsWith("Dilithium")
            || publicKey instanceof MLDSAKey)) {
      return new MlDsaVerifier(publicKey);
    }
    throw new UnsupportedAlgorithmException(
        "Cannot verify signatures for key type '"
            + publicKey.getAlgorithm()
            + "', this client only supports ML-DSA verification in PQC verifiers");
  }
}
