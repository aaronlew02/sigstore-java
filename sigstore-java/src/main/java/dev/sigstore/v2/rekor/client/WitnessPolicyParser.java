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

import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableMap;
import dev.sigstore.rekor.client.RekorParseException;
import dev.sigstore.v2.encryption.Keys;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.encoders.Hex;

/**
 * Parser for C2SP / Sigsum witness policy configuration files.
 *
 * <p>Specification:
 *
 * <ul>
 *   <li><a href="https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/policy.md">Sigsum
 *       Policy</a>
 *   <li><a href="https://github.com/C2SP/C2SP/blob/main/signed-note.md#verifier-keys">C2SP Signed
 *       Note Verifier Keys</a>
 * </ul>
 */
final class WitnessPolicyParser {

  private static final String QUORUM_NONE = "none";

  // OIDs for post-quantum algorithms
  private static final ASN1ObjectIdentifier OID_ML_DSA_44 =
      new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.17");
  private static final ASN1ObjectIdentifier OID_ML_DSA_65 =
      new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.18");
  private static final ASN1ObjectIdentifier OID_ML_DSA_87 =
      new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.19");

  private static class GroupNode {
    final int threshold;
    final List<String> members;

    GroupNode(int threshold, List<String> members) {
      this.threshold = threshold;
      this.members = members;
    }
  }

  public static WitnessPolicy parse(String policyConfig) throws RekorParseException {
    if (policyConfig == null || policyConfig.trim().isEmpty()) {
      throw new RekorParseException("Witness policy configuration string is empty");
    }

    Map<String, GroupNode> groups = new LinkedHashMap<>();
    Map<String, VerifierKey> verifierKeys = new LinkedHashMap<>();
    Set<String> definedSymbols = new HashSet<>();
    String quorumTarget = null;

    List<String> lines = Splitter.onPattern("\r?\n").splitToList(policyConfig);

    for (int lineNum = 1; lineNum <= lines.size(); lineNum++) {
      String line = lines.get(lineNum - 1).trim();
      if (line.isEmpty() || line.startsWith("#")) {
        continue;
      }

      List<String> tokens = Splitter.onPattern("[ \\t]+").omitEmptyStrings().splitToList(line);
      if (tokens.isEmpty()) {
        continue;
      }

      String directive = tokens.get(0);

      switch (directive) {
        case "witness":
          {
            if (tokens.size() < 3 || tokens.size() > 4) {
              throw new RekorParseException(
                  "Invalid witness directive on line " + lineNum + ": " + line);
            }
            String name = tokens.get(1);
            String pubKeyStr = tokens.get(2);

            if (QUORUM_NONE.equals(name)) {
              throw new RekorParseException(
                  "Witness name cannot be '" + QUORUM_NONE + "' on line " + lineNum);
            }
            if (definedSymbols.contains(name)) {
              throw new RekorParseException(
                  "Duplicate symbol name '" + name + "' defined on line " + lineNum);
            }

            VerifierKey verifierKey;
            try {
              verifierKey = parseVerifierKey(pubKeyStr);
            } catch (GeneralSecurityException | IllegalArgumentException e) {
              throw new RekorParseException(
                  "Failed to parse public key for witness '" + name + "' on line " + lineNum, e);
            }

            for (VerifierKey existing : verifierKeys.values()) {
              if (Arrays.equals(
                  existing.getPublicKey().getEncoded(), verifierKey.getPublicKey().getEncoded())) {
                throw new RekorParseException(
                    "Duplicate public key for witness '" + name + "' on line " + lineNum);
              }
            }

            verifierKeys.put(name, verifierKey);
            definedSymbols.add(name);
            break;
          }

        case "group":
          {
            if (tokens.size() < 4) {
              throw new RekorParseException(
                  "Invalid group directive on line " + lineNum + ": " + line);
            }
            String groupName = tokens.get(1);
            String rule = tokens.get(2);
            List<String> members = tokens.subList(3, tokens.size());

            if (QUORUM_NONE.equals(groupName)) {
              throw new RekorParseException(
                  "Group name cannot be '" + QUORUM_NONE + "' on line " + lineNum);
            }
            if (definedSymbols.contains(groupName)) {
              throw new RekorParseException(
                  "Duplicate symbol name '" + groupName + "' defined on line " + lineNum);
            }

            Set<String> memberSet = new HashSet<>();
            for (String member : members) {
              if (!definedSymbols.contains(member)) {
                throw new RekorParseException(
                    "Group '"
                        + groupName
                        + "' references undefined member '"
                        + member
                        + "' on line "
                        + lineNum);
              }
              if (!memberSet.add(member)) {
                throw new RekorParseException(
                    "Duplicate member '"
                        + member
                        + "' in group '"
                        + groupName
                        + "' on line "
                        + lineNum);
              }
            }

            int threshold;
            int totalMembers = members.size();
            if ("all".equalsIgnoreCase(rule)) {
              threshold = totalMembers;
            } else if ("any".equalsIgnoreCase(rule)) {
              threshold = 1;
            } else {
              try {
                threshold = Integer.parseInt(rule);
              } catch (NumberFormatException e) {
                throw new RekorParseException(
                    "Invalid group threshold '" + rule + "' on line " + lineNum);
              }
              if (threshold < 1 || threshold > totalMembers) {
                throw new RekorParseException(
                    "Threshold "
                        + threshold
                        + " out of bounds for group of size "
                        + totalMembers
                        + " on line "
                        + lineNum);
              }
            }

            GroupNode groupNode = new GroupNode(threshold, new ArrayList<>(members));
            groups.put(groupName, groupNode);
            definedSymbols.add(groupName);
            break;
          }

        case "quorum":
          {
            if (tokens.size() != 2) {
              throw new RekorParseException(
                  "Invalid quorum directive on line " + lineNum + ": " + line);
            }
            if (quorumTarget != null) {
              throw new RekorParseException(
                  "Multiple quorum directives found; only one is allowed (line " + lineNum + ")");
            }
            String target = tokens.get(1);
            if (!QUORUM_NONE.equals(target) && !definedSymbols.contains(target)) {
              throw new RekorParseException(
                  "Quorum target '" + target + "' is undefined on line " + lineNum);
            }
            quorumTarget = target;
            break;
          }

        case "log":
          // Log lines are allowed per Sigsum policy spec, ignored for witness verification
          break;

        default:
          throw new RekorParseException("Unknown directive '" + directive + "' on line " + lineNum);
      }
    }

    if (quorumTarget == null) {
      throw new RekorParseException("Witness policy is missing a 'quorum' directive");
    }

    final String finalQuorumTarget = quorumTarget;
    final Map<String, VerifierKey> immutableVerifierKeys = ImmutableMap.copyOf(verifierKeys);

    return new WitnessPolicy() {
      @Override
      public boolean isSatisfied(Set<String> verified) {
        if (QUORUM_NONE.equals(finalQuorumTarget)) {
          return true;
        }
        if (verified == null || verified.isEmpty()) {
          return false;
        }
        return evaluateNode(finalQuorumTarget, verified);
      }

      private boolean evaluateNode(String nodeName, Set<String> verified) {
        if (immutableVerifierKeys.containsKey(nodeName)) {
          return verified.contains(nodeName);
        }
        if (groups.containsKey(nodeName)) {
          GroupNode g = groups.get(nodeName);
          int satisfiedCount = 0;
          for (String member : g.members) {
            if (evaluateNode(member, verified)) {
              satisfiedCount++;
            }
          }
          return satisfiedCount >= g.threshold;
        }
        return false;
      }

      @Override
      public Map<String, VerifierKey> getWitnessVerifierKeys() {
        return immutableVerifierKeys;
      }
    };
  }

  private static VerifierKey parseVerifierKey(String vkey) throws GeneralSecurityException {
    List<String> parts = Splitter.on('+').limit(3).splitToList(vkey);
    if (parts.size() != 3 || parts.get(0).isEmpty() || !parts.get(1).matches("^[0-9a-fA-F]{8}$")) {
      throw new GeneralSecurityException("Witness key is not a vkey: " + vkey);
    }
    byte[] payload;
    try {
      payload = Base64.getDecoder().decode(parts.get(2));
    } catch (IllegalArgumentException e) {
      throw new GeneralSecurityException("Invalid base64 in verifier key payload", e);
    }
    return ImmutableVerifierKey.builder()
        .name(parts.get(0))
        .keyId(Hex.decode(parts.get(1)))
        .publicKey(parseKeyPayload(payload))
        .build();
  }

  private static PublicKey parseKeyPayload(byte[] payload) throws GeneralSecurityException {
    if (payload == null || payload.length == 0) {
      throw new GeneralSecurityException("Empty key payload");
    }

    byte algByte = payload[0];

    // C2SP note format post-quantum alg identifiers:
    // 0x06 = ML-DSA-44 (1312 bytes raw key)
    if (algByte == 0x06 && payload.length == 1313) {
      byte[] raw = Arrays.copyOfRange(payload, 1, payload.length);
      return createMlDsaPublicKey(OID_ML_DSA_44, raw);
    }

    // 0x07 = ML-DSA-65 (1952 bytes raw key)
    if (algByte == 0x07 && payload.length == 1953) {
      byte[] raw = Arrays.copyOfRange(payload, 1, payload.length);
      return createMlDsaPublicKey(OID_ML_DSA_65, raw);
    }

    // 0x08 = ML-DSA-87 (2592 bytes raw key)
    if (algByte == 0x08 && payload.length == 2593) {
      byte[] raw = Arrays.copyOfRange(payload, 1, payload.length);
      return createMlDsaPublicKey(OID_ML_DSA_87, raw);
    }

    throw new GeneralSecurityException(
        "Unsupported non-PQC or invalid key payload with leading byte: "
            + String.format(Locale.ROOT, "0x%02x", algByte)
            + ", length: "
            + payload.length
            + "; only ML-DSA (44, 65, 87) is supported");
  }

  private static PublicKey createMlDsaPublicKey(ASN1ObjectIdentifier oid, byte[] rawKeyBytes)
      throws GeneralSecurityException {
    try {
      SubjectPublicKeyInfo spki =
          new SubjectPublicKeyInfo(new AlgorithmIdentifier(oid), rawKeyBytes);
      return Keys.parseMlDsa(spki.getEncoded());
    } catch (IOException e) {
      throw new GeneralSecurityException(
          "Failed to encode ML-DSA SPKI structure: " + e.getMessage(), e);
    }
  }
}
