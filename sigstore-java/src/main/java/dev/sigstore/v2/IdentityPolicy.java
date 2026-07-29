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

import dev.sigstore.KeylessVerificationException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.immutables.value.Value;

/** The identity that a log entry must have: an issuer, an identity, and optional other claims. */
@Value.Immutable
public interface IdentityPolicy {

  /** The expected identity (the SAN), compared with the logged "identity" claim. */
  String getIdentity();

  /** The expected issuer, compared with the logged "issuer" claim. */
  String getIssuer();

  /** Expected values of other logged claims, such as "source-repository-uri". */
  Map<String, String> getAdditionalClaims();

  /**
   * Checks that each expected claim is logged with exactly the expected value. Logged claims that
   * are not expected are ignored.
   *
   * @throws KeylessVerificationException if an expected claim is missing or has a different value
   */
  default void checkClaims(Map<String, String> loggedClaims) throws KeylessVerificationException {
    Map<String, String> expected = new LinkedHashMap<>();
    expected.put("issuer", getIssuer());
    expected.put("identity", getIdentity());
    expected.putAll(getAdditionalClaims());
    for (Map.Entry<String, String> claim : expected.entrySet()) {
      String logged = loggedClaims.get(claim.getKey());
      if (logged == null) {
        throw new KeylessVerificationException(
            "tlog proof has no \"" + claim.getKey() + "\" claim");
      }
      if (!logged.equals(claim.getValue())) {
        throw new KeylessVerificationException(
            "logged "
                + claim.getKey()
                + " \""
                + logged
                + "\" does not match the expected "
                + claim.getKey()
                + " \""
                + claim.getValue()
                + "\"");
      }
    }
  }

  @Value.Check
  default void checkReservedClaims() {
    if (getAdditionalClaims().containsKey("issuer")
        || getAdditionalClaims().containsKey("identity")) {
      throw new IllegalStateException(
          "set the issuer and identity with their own fields, not as additional claims");
    }
  }

  static ImmutableIdentityPolicy.Builder builder() {
    return ImmutableIdentityPolicy.builder();
  }
}
