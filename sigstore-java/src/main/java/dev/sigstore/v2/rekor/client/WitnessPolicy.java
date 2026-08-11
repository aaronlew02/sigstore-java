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

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import dev.sigstore.rekor.client.RekorParseException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Policy for verifying multiple witness signatures, as defined by the C2SP transparency log policy
 * (https://c2sp.org/tlog-policy). A policy is satisfied if the given set of verified witness
 * cosignatures satisfies this policy. See also
 * https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/policy.md.
 */
public final class WitnessPolicy {

  static final String QUORUM_NONE = "none";

  private static final WitnessPolicy QUORUM_NONE_POLICY =
      new WitnessPolicy(QUORUM_NONE, Map.of(), Map.of());

  static final class Group {
    final int threshold;
    final List<String> members;

    Group(int threshold, List<String> members) {
      this.threshold = threshold;
      this.members = List.copyOf(members);
    }
  }

  private final String quorum;
  private final Map<String, VerifierKey> witnesses;
  private final Map<String, Group> groups;

  WitnessPolicy(String quorum, Map<String, VerifierKey> witnesses, Map<String, Group> groups) {
    this.quorum = Preconditions.checkNotNull(quorum, "quorum cannot be null");
    this.witnesses = ImmutableMap.copyOf(witnesses);
    this.groups = ImmutableMap.copyOf(groups);

    Preconditions.checkArgument(
        !this.witnesses.containsKey(QUORUM_NONE), "Witness name cannot be '%s'", QUORUM_NONE);
    Preconditions.checkArgument(
        !this.groups.containsKey(QUORUM_NONE), "Group name cannot be '%s'", QUORUM_NONE);

    Map<String, byte[]> encodedKeys = new LinkedHashMap<>();
    for (Map.Entry<String, VerifierKey> witness : this.witnesses.entrySet()) {
      Preconditions.checkArgument(
          !this.groups.containsKey(witness.getKey()),
          "Name '%s' is both a witness and a group",
          witness.getKey());
      byte[] encodedKey = witness.getValue().getPublicKey().getEncoded();
      for (Map.Entry<String, byte[]> other : encodedKeys.entrySet()) {
        Preconditions.checkArgument(
            !Arrays.equals(other.getValue(), encodedKey),
            "Witnesses '%s' and '%s' have the same public key",
            other.getKey(),
            witness.getKey());
      }
      encodedKeys.put(witness.getKey(), encodedKey);
    }

    for (Map.Entry<String, Group> group : this.groups.entrySet()) {
      Group g = group.getValue();
      Preconditions.checkArgument(
          g.threshold >= 1 && g.threshold <= g.members.size(),
          "Threshold %s out of bounds for group '%s' of size %s",
          g.threshold,
          group.getKey(),
          g.members.size());
      Set<String> memberSet = new HashSet<>();
      for (String member : g.members) {
        Preconditions.checkArgument(
            memberSet.add(member), "Duplicate member '%s' in group '%s'", member, group.getKey());
        Preconditions.checkArgument(
            this.witnesses.containsKey(member) || this.groups.containsKey(member),
            "Group '%s' references undefined member '%s'",
            group.getKey(),
            member);
      }
    }

    Set<String> acyclicGroups = new HashSet<>();
    for (String groupName : this.groups.keySet()) {
      checkAcyclic(groupName, new HashSet<>(), acyclicGroups);
    }

    Preconditions.checkArgument(
        QUORUM_NONE.equals(quorum)
            || this.witnesses.containsKey(quorum)
            || this.groups.containsKey(quorum),
        "Quorum target '%s' is undefined",
        quorum);
  }

  private void checkAcyclic(String groupName, Set<String> path, Set<String> acyclicGroups) {
    if (acyclicGroups.contains(groupName)) {
      return;
    }
    Preconditions.checkArgument(path.add(groupName), "Group '%s' contains itself", groupName);
    for (String member : groups.get(groupName).members) {
      if (groups.containsKey(member)) {
        checkAcyclic(member, path, acyclicGroups);
      }
    }
    path.remove(groupName);
    acyclicGroups.add(groupName);
  }

  /**
   * Checks if the given set of verified witness cosignatures, by witness policy name, satisfies
   * this policy.
   */
  public boolean isSatisfied(Set<String> verified) {
    if (QUORUM_NONE.equals(quorum)) {
      return true;
    }
    if (verified == null || verified.isEmpty()) {
      return false;
    }
    return evaluateNode(quorum, verified);
  }

  private boolean evaluateNode(String nodeName, Set<String> verified) {
    if (witnesses.containsKey(nodeName)) {
      return verified.contains(nodeName);
    }
    Group g = groups.get(nodeName);
    int satisfiedCount = 0;
    for (String member : g.members) {
      if (evaluateNode(member, verified)) {
        satisfiedCount++;
      }
    }
    return satisfiedCount >= g.threshold;
  }

  /** Returns the map of witness policy names to their verifier keys. */
  public Map<String, VerifierKey> getWitnessVerifierKeys() {
    return witnesses;
  }

  /** Returns the policy {@code quorum none}, which requires no witness cosignatures. */
  public static WitnessPolicy quorumNone() {
    return QUORUM_NONE_POLICY;
  }

  /**
   * Parses a C2SP / Sigsum witness policy configuration string into a {@link WitnessPolicy}.
   *
   * @param policyConfig the policy string
   * @return the parsed WitnessPolicy
   * @throws RekorParseException if the policy string is invalid
   */
  public static WitnessPolicy from(String policyConfig) throws RekorParseException {
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
  public static WitnessPolicy from(Path policyPath) throws IOException, RekorParseException {
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
  public static WitnessPolicy from(InputStream inputStream)
      throws IOException, RekorParseException {
    Preconditions.checkNotNull(inputStream, "inputStream cannot be null");
    return WitnessPolicyParser.parse(
        new String(inputStream.readAllBytes(), StandardCharsets.UTF_8));
  }
}
