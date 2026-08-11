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

import com.google.common.io.Resources;
import dev.sigstore.trustroot.ImmutableSigstoreTrustedRoot;
import dev.sigstore.trustroot.SigstoreConfigurationException;
import dev.sigstore.trustroot.SigstoreTrustedRoot;
import dev.sigstore.v2.AlgorithmRegistry;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class VerifierKeyTest {

  private static final String STAGING_ROOT = "dev/sigstore/v2/trustroot/staging_trusted_root.json";
  private static final String CLASSICAL_ROOT = "dev/sigstore/trustroot/staging_trusted_root.json";

  private static SigstoreTrustedRoot load(String resource) throws Exception {
    try (var is = Resources.getResource(resource).openStream()) {
      return SigstoreTrustedRoot.from(is);
    }
  }

  @Test
  public void fromTrustedRoot() throws Exception {
    var keys = VerifierKey.fromTrustedRoot(load(STAGING_ROOT));

    Assertions.assertEquals(1, keys.size());
    var key = keys.get(0);
    Assertions.assertEquals("pqc27-a1.us-east4.rekor.sigstage.dev", key.getName());
    Assertions.assertEquals("c9a9945c", Hex.toHexString(key.getKeyId()));
    Assertions.assertEquals(
        AlgorithmRegistry.SigningAlgorithm.ML_DSA_44,
        AlgorithmRegistry.getSigningAlgorithm(key.getPublicKey()));
  }

  @Test
  public void fromTrustedRoot_skipsClassicalLogs() throws Exception {
    var mixed =
        ImmutableSigstoreTrustedRoot.builder()
            .addAllTLogs(load(CLASSICAL_ROOT).getTLogs())
            .addAllTLogs(load(STAGING_ROOT).getTLogs())
            .build();

    var keys = VerifierKey.fromTrustedRoot(mixed);

    Assertions.assertEquals(1, keys.size());
    Assertions.assertEquals("pqc27-a1.us-east4.rekor.sigstage.dev", keys.get(0).getName());
  }

  @Test
  public void fromTrustedRoot_noMlDsaLog_throws() throws Exception {
    var classical = load(CLASSICAL_ROOT);

    var ex =
        Assertions.assertThrows(
            SigstoreConfigurationException.class, () -> VerifierKey.fromTrustedRoot(classical));
    Assertions.assertEquals(
        "Trusted root has no transparency log with an ML-DSA key", ex.getMessage());
  }
}
