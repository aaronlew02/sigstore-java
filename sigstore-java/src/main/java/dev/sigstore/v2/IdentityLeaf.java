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

import com.google.common.hash.Hasher;
import com.google.common.hash.Hashing;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

/** Computes c2sp.org/identity-transparency v1 leaf hashes for OIDC log entries. */
public final class IdentityLeaf {
  private static final byte RFC6962_LEAF_PREFIX = 0x00;
  private static final byte LEAF_VERSION_V1 = 0x01;
  private static final int RECEIPT_SIZE = 32;

  private IdentityLeaf() {}

  /** Leaf hash for an OIDC entry with the given issuer and logged claims. */
  public static byte[] oidcLeafHash(
      byte[] artifactDigest, String issuer, Map<String, String> claims) {
    Hasher leaf =
        Hashing.sha256()
            .newHasher()
            .putByte(RFC6962_LEAF_PREFIX)
            .putByte(LEAF_VERSION_V1)
            .putBytes(sha256(issuer.getBytes(StandardCharsets.UTF_8)))
            .putBytes(sha256(artifactDigest));
    claims.entrySet().stream()
        .map(e -> new HashedClaim(doubleSha256(e.getKey()), doubleSha256(e.getValue())))
        .sorted((a, b) -> Arrays.compareUnsigned(a.keyHash, b.keyHash))
        .forEachOrdered(c -> leaf.putBytes(c.keyHash).putBytes(c.valueHash));
    return leaf.putBytes(new byte[RECEIPT_SIZE]).hash().asBytes();
  }

  private static byte[] sha256(byte[] input) {
    return Hashing.sha256().hashBytes(input).asBytes();
  }

  private static byte[] doubleSha256(String input) {
    return sha256(sha256(input.getBytes(StandardCharsets.UTF_8)));
  }

  private static final class HashedClaim {
    private final byte[] keyHash;
    private final byte[] valueHash;

    private HashedClaim(byte[] keyHash, byte[] valueHash) {
      this.keyHash = keyHash;
      this.valueHash = valueHash;
    }
  }
}
