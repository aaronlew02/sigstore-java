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
package dev.sigstore.rekor.v3.client;

import com.google.common.base.Preconditions;
import dev.sigstore.rekor.client.RekorParseException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Map;
import java.util.Set;

/**
 * Interface for defining policies for verifying multiple witness signatures. A policy is satisfied
 * if the given set of verified witness cosignatures satisfies this policy. See
 * https://github.com/C2SP/C2SP/pull/233 and
 * https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/policy.md.
 */
public interface WitnessPolicy {

  /** Checks if the given set of verified witness cosignatures satisfies this policy. */
  boolean isSatisfied(Set<String> verified);

  /** Returns the map of trusted witness identities (and aliases) to their public keys. */
  default Map<String, PublicKey> getWitnessPublicKeys() {
    return Map.of();
  }

  /** Policy that requires no witness cosignatures. */
  WitnessPolicy NONE = verifiedWitnesses -> true;

  /**
   * Parses a C2SP / Sigsum witness policy configuration string into a {@link WitnessPolicy}.
   *
   * @param policyConfig the policy string
   * @return the parsed WitnessPolicy
   * @throws RekorParseException if the policy string is invalid
   */
  static WitnessPolicy from(String policyConfig) throws RekorParseException {
    Preconditions.checkNotNull(policyConfig, "policyConfig cannot be null");
    return WitnessPolicyParser.parse(policyConfig);
  }

  /**
   * Parses a C2SP / Sigsum witness policy configuration file into a {@link WitnessPolicy}.
   *
   * @param policyPath path to the policy file
   * @return the parsed WitnessPolicy
   * @throws IOException if the file cannot be read
   * @throws RekorParseException if the policy content is invalid
   */
  static WitnessPolicy from(Path policyPath) throws IOException, RekorParseException {
    Preconditions.checkNotNull(policyPath, "policyPath cannot be null");
    try (var is = Files.newInputStream(policyPath)) {
      return from(is);
    }
  }

  /**
   * Parses a C2SP / Sigsum witness policy configuration input stream into a {@link WitnessPolicy}.
   *
   * @param inputStream input stream of the policy file
   * @return the parsed WitnessPolicy
   * @throws IOException if reading from the stream fails
   * @throws RekorParseException if the policy content is invalid
   */
  static WitnessPolicy from(InputStream inputStream) throws IOException, RekorParseException {
    Preconditions.checkNotNull(inputStream, "inputStream cannot be null");
    return WitnessPolicyParser.parse(
        new String(inputStream.readAllBytes(), StandardCharsets.UTF_8));
  }
}
