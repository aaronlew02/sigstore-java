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

import dev.sigstore.UnsupportedAlgorithmException;
import dev.sigstore.trustroot.SigstoreConfigurationException;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import dev.sigstore.trustroot.TransparencyLog;
import dev.sigstore.v2.AlgorithmRegistry;
import dev.sigstore.v2.encryption.Keys;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.immutables.value.Value.Immutable;

@Immutable
public interface VerifierKey {

  String getName();

  byte[] getKeyId();

  PublicKey getPublicKey();

  static List<VerifierKey> fromTrustedRoot(SigstoreTrustedRoot trustedRoot)
      throws SigstoreConfigurationException {
    List<VerifierKey> keys = new ArrayList<>();
    for (TransparencyLog tlog : trustedRoot.getTLogs()) {
      String keyDetails = tlog.getPublicKey().getKeyDetails();
      if (!keyDetails.startsWith("ML_DSA_")) {
        continue;
      }
      String name = tlog.getBaseUrl().getHost();
      if (name == null) {
        throw new SigstoreConfigurationException(
            "Transparency log base URL has no host: " + tlog.getBaseUrl());
      }
      byte[] logId = tlog.getLogId().getKeyId();
      if (logId.length < 4) {
        throw new SigstoreConfigurationException(
            "Log ID of transparency log " + name + " is shorter than a key ID");
      }
      PublicKey publicKey;
      try {
        publicKey = Keys.parseMlDsa(tlog.getPublicKey().getRawBytes());
        if (!AlgorithmRegistry.getSigningAlgorithm(publicKey).name().equals(keyDetails)) {
          throw new SigstoreConfigurationException(
              "Key of transparency log " + name + " does not match its key details " + keyDetails);
        }
      } catch (InvalidKeySpecException | UnsupportedAlgorithmException ex) {
        throw new SigstoreConfigurationException(
            "Could not parse the ML-DSA key of transparency log " + name, ex);
      }
      keys.add(
          ImmutableVerifierKey.builder()
              .name(name)
              .keyId(Arrays.copyOf(logId, 4))
              .publicKey(publicKey)
              .build());
    }
    if (keys.isEmpty()) {
      throw new SigstoreConfigurationException(
          "Trusted root has no transparency log with an ML-DSA key");
    }
    return keys;
  }
}
