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

import com.google.common.base.Splitter;
import dev.sigstore.AlgorithmRegistryPqc;
import dev.sigstore.UnsupportedAlgorithmException;
import dev.sigstore.rekor.client.RekorParseException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private static final String QUORUM_NONE = "none";

  // OIDs for post-quantum algorithms
  private static final ASN1ObjectIdentifier OID_ML_DSA_44 =
      new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.17");
  private static final ASN1ObjectIdentifier OID_ML_DSA_65 =
      new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.18");
  private static final ASN1ObjectIdentifier OID_ML_DSA_87 =
      new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.19");

  private static class WitnessNode {
    final String alias;
    final String identity;

    WitnessNode(String alias, String identity) {
      this.alias = alias;
      this.identity = identity;
    }
  }

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

    Map<String, WitnessNode> witnesses = new LinkedHashMap<>();
    Map<String, GroupNode> groups = new LinkedHashMap<>();
    Map<String, PublicKey> publicKeys = new HashMap<>();
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
            if (tokens.size() < 3) {
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

            ParsedKey parsedKey;
            try {
              parsedKey = parseVerifierKey(pubKeyStr, name);
            } catch (GeneralSecurityException | IllegalArgumentException e) {
              throw new RekorParseException(
                  "Failed to parse public key for witness '" + name + "' on line " + lineNum, e);
            }

            WitnessNode node = new WitnessNode(name, parsedKey.identity);
            witnesses.put(name, node);
            definedSymbols.add(name);

            publicKeys.put(parsedKey.identity, parsedKey.publicKey);
            publicKeys.put(name, parsedKey.publicKey);
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
    final Map<String, PublicKey> immutablePublicKeys = Collections.unmodifiableMap(publicKeys);

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
        if (witnesses.containsKey(nodeName)) {
          WitnessNode w = witnesses.get(nodeName);
          return verified.contains(w.identity) || verified.contains(w.alias);
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
      public Map<String, PublicKey> getWitnessPublicKeys() {
        return immutablePublicKeys;
      }
    };
  }

  private static class ParsedKey {
    final String identity;
    final PublicKey publicKey;

    ParsedKey(String identity, PublicKey publicKey) {
      this.identity = identity;
      this.publicKey = publicKey;
    }
  }

  private static ParsedKey parseVerifierKey(String keyString, String fallbackIdentity)
      throws GeneralSecurityException {
    // Check for C2SP signed note verifier key format: <identity>+<keyhash>+<base64-payload>
    int firstPlus = keyString.indexOf('+');
    if (firstPlus > 0) {
      int secondPlus = keyString.indexOf('+', firstPlus + 1);
      if (secondPlus > firstPlus + 1) {
        String keyHash = keyString.substring(firstPlus + 1, secondPlus);
        if (keyHash.length() == 8 && keyHash.matches("^[0-9a-fA-F]{8}$")) {
          String identity = keyString.substring(0, firstPlus);
          String b64Payload = keyString.substring(secondPlus + 1);
          try {
            byte[] payload = Base64.getDecoder().decode(b64Payload);
            PublicKey publicKey = parseKeyPayload(payload);
            return new ParsedKey(identity, publicKey);
          } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Invalid base64 in verifier key payload", e);
          }
        }
      }
    }

    // Try base64-encoded raw ML-DSA payload or SPKI DER
    try {
      byte[] b64Bytes = Base64.getDecoder().decode(keyString);
      PublicKey pubKey = parseKeyPayload(b64Bytes);
      return new ParsedKey(fallbackIdentity, pubKey);
    } catch (IllegalArgumentException ignored) {
    }

    throw new GeneralSecurityException(
        "Unrecognized or non-PQC public key format: " + keyString + "; only ML-DSA is supported");
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

    // If payload starts with ASN.1 SEQUENCE (0x30), attempt SPKI decoding
    if (algByte == 0x30) {
      return parseSpki(payload);
    }

    // Raw ML-DSA lengths without alg byte
    if (payload.length == 1312) {
      return createMlDsaPublicKey(OID_ML_DSA_44, payload);
    }
    if (payload.length == 1952) {
      return createMlDsaPublicKey(OID_ML_DSA_65, payload);
    }
    if (payload.length == 2592) {
      return createMlDsaPublicKey(OID_ML_DSA_87, payload);
    }

    throw new GeneralSecurityException(
        "Unsupported non-PQC or invalid key payload with leading byte: "
            + String.format("0x%02x", algByte)
            + ", length: "
            + payload.length
            + "; only ML-DSA (44, 65, 87) is supported");
  }

  private static PublicKey createMlDsaPublicKey(ASN1ObjectIdentifier oid, byte[] rawKeyBytes)
      throws GeneralSecurityException {
    try {
      SubjectPublicKeyInfo spki =
          new SubjectPublicKeyInfo(new AlgorithmIdentifier(oid), rawKeyBytes);
      return parseSpki(spki.getEncoded());
    } catch (IOException e) {
      throw new GeneralSecurityException(
          "Failed to encode ML-DSA SPKI structure: " + e.getMessage(), e);
    }
  }

  private static PublicKey parseSpki(byte[] spkiBytes) throws GeneralSecurityException {
    try {
      X509EncodedKeySpec spec = new X509EncodedKeySpec(spkiBytes);
      PublicKey pubKey = KeyFactory.getInstance("ML-DSA", "BC").generatePublic(spec);
      AlgorithmRegistryPqc.getSigningAlgorithm(pubKey);
      return pubKey;
    } catch (UnsupportedAlgorithmException e) {
      throw new GeneralSecurityException("Unsupported key algorithm in SPKI: " + e.getMessage(), e);
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      throw new GeneralSecurityException("Failed to decode SPKI public key: " + e.getMessage(), e);
    }
  }
}
