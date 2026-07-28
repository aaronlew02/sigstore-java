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
package dev.sigstore.encryption.signers;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/** ML-DSA verifier, instantiated by {@link Verifiers#newVerifier(PublicKey)}. */
class MlDsaVerifier implements Verifier {

  private final PublicKey publicKey;

  MlDsaVerifier(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  @Override
  public PublicKey getPublicKey() {
    return publicKey;
  }

  /** ML-DSA verifiers hash implicitly as part of the ML-DSA signature scheme. */
  @Override
  public boolean verify(byte[] artifact, byte[] signature)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    var verifier = Signature.getInstance(publicKey.getAlgorithm());
    verifier.initVerify(publicKey);
    verifier.update(artifact);
    return verifier.verify(signature);
  }

  @Override
  public boolean verifyDigest(byte[] digest, byte[] signature) {
    throw new UnsupportedOperationException(
        "ML-DSA verification requires an artifact, not a digest.");
  }
}
