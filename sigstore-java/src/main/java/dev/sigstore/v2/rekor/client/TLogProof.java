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

import dev.sigstore.rekor.client.RekorParseException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.immutables.value.Value;

/** Represents a Transparency Log Proof as defined by the c2sp.org/tlog-proof@v1 specification. */
@Value.Immutable
public interface TLogProof {

  String TLOG_PROOF_VERSION = "c2sp.org/tlog-proof@v1";

  /** The log index. */
  long getLogIndex();

  /** The Merkle inclusion proof hashes. */
  List<byte[]> getHashes();

  /** The raw checkpoint string. */
  String getCheckpoint();

  /** The list of raw extra payloads. */
  List<byte[]> getExtra();

  /**
   * Parses the claim lines of the extra line into a map from claim name to decoded value. Each
   * claim line is {@code name:Base64(value)}.
   *
   * @throws RekorParseException if the extra line or a claim line is malformed
   */
  default Map<String, String> parseExtraData() throws RekorParseException {
    if (getExtra().isEmpty()) {
      return Collections.emptyMap();
    }
    if (getExtra().size() > 1) {
      throw new RekorParseException("tlog proof has more than one extra line");
    }
    String[] claimLines = new String(getExtra().get(0), StandardCharsets.UTF_8).split("\n");
    Map<String, String> claims = new HashMap<>();
    for (int i = 0; i < claimLines.length; i++) {
      int colon = claimLines[i].indexOf(':');
      if (colon <= 0) {
        throw new RekorParseException(
            "claim line " + (i + 1) + " is not in the form name:Base64(value)");
      }
      String name = claimLines[i].substring(0, colon);
      byte[] value;
      try {
        value = Base64.getDecoder().decode(claimLines[i].substring(colon + 1));
      } catch (IllegalArgumentException ex) {
        throw new RekorParseException("claim value of \"" + name + "\" is not valid base64", ex);
      }
      if (claims.putIfAbsent(name, new String(value, StandardCharsets.UTF_8)) != null) {
        throw new RekorParseException("claim name \"" + name + "\" appears more than once");
      }
    }
    return Collections.unmodifiableMap(claims);
  }

  /** Reconstructs the exact c2sp.org/tlog-proof@v1 textual format. */
  default String toProofString() {
    StringBuilder sb = new StringBuilder();
    sb.append(TLOG_PROOF_VERSION).append("\n");
    for (byte[] e : getExtra()) {
      sb.append("extra ").append(Base64.getEncoder().encodeToString(e)).append("\n");
    }
    sb.append("index ").append(getLogIndex()).append("\n");
    for (byte[] hash : getHashes()) {
      sb.append(Base64.getEncoder().encodeToString(hash)).append("\n");
    }
    sb.append("\n");
    sb.append(getCheckpoint());
    return sb.toString();
  }

  /** Parses a raw byte array containing a c2sp.org/tlog-proof@v1 formatted proof. */
  static TLogProof parse(byte[] proofBytes) {
    String proofStr = new String(proofBytes, StandardCharsets.UTF_8);
    String[] lines = proofStr.split("\n");

    if (lines.length == 0 || !lines[0].trim().equals(TLOG_PROOF_VERSION)) {
      throw new IllegalArgumentException("Invalid TLogProof version or format");
    }

    ImmutableTLogProof.Builder builder = ImmutableTLogProof.builder();
    long parsedIndex = -1;

    int i = 1;
    // Parse extra and index
    for (; i < lines.length; i++) {
      String line = lines[i].trim();
      if (line.startsWith("extra ")) {
        String base64Extra = line.substring(6);
        builder.addExtra(Base64.getDecoder().decode(base64Extra));
      } else if (line.startsWith("index ")) {
        parsedIndex = Long.parseLong(line.substring(6).trim());
        builder.logIndex(parsedIndex);
        i++;
        break;
      }
    }

    // Parse hashes until empty line
    for (; i < lines.length; i++) {
      String line = lines[i].trim();
      if (line.isEmpty()) {
        i++;
        break; // Empty line separates hashes from checkpoint
      }
      builder.addHashes(Base64.getDecoder().decode(line));
    }

    // Parse checkpoint (the rest of the lines)
    StringBuilder parsedCheckpoint = new StringBuilder();
    for (; i < lines.length; i++) {
      parsedCheckpoint.append(lines[i]).append("\n");
    }
    builder.checkpoint(parsedCheckpoint.toString());

    if (parsedIndex == -1) {
      throw new IllegalArgumentException("TLogProof missing 'index' line");
    }

    return builder.build();
  }
}
