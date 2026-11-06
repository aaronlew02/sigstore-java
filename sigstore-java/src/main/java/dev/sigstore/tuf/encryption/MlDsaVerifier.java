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

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

class MlDsaVerifier implements Verifier {

  private static final byte[] TAP21_V1_PREFIX = {0x74, 0x75, 0x66, 0x01};

  private final PublicKey publicKey;

  MlDsaVerifier(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  @Override
  public boolean verify(byte[] artifact, byte[] signature)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Signature verifier;
    try {
      verifier = Signature.getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME);
    } catch (NoSuchProviderException e) {
      throw new NoSuchAlgorithmException(e);
    }
    verifier.initVerify(publicKey);
    verifier.update(TAP21_V1_PREFIX);
    verifier.update(MessageDigest.getInstance("SHA-512").digest(artifact));
    return verifier.verify(signature);
  }
}
