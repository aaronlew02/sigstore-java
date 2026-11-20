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
package dev.sigstore.v2.encryption;

import dev.sigstore.UnsupportedAlgorithmException;
import dev.sigstore.v2.AlgorithmRegistry;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Keys {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public static PublicKey parseMlDsa(byte[] contents) throws InvalidKeySpecException {
    try {
      var keySpec = new X509EncodedKeySpec(contents);
      var factory = KeyFactory.getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME);
      var key = factory.generatePublic(keySpec);
      AlgorithmRegistry.getSigningAlgorithm(key);
      return key;
    } catch (UnsupportedAlgorithmException e) {
      throw new InvalidKeySpecException("Unsupported ML-DSA key: " + e.getMessage(), e);
    } catch (IllegalArgumentException
        | IllegalStateException
        | NullPointerException
        | ArrayIndexOutOfBoundsException e) {
      throw new InvalidKeySpecException(e);
    } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
