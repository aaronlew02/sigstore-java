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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.sigstore.KeylessVerificationException;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class IdentityPolicyTest {

  private static final String ISSUER = "https://issuer.example";
  private static final String IDENTITY = "user@example.com";
  private static final IdentityPolicy POLICY =
      IdentityPolicy.builder().issuer(ISSUER).identity(IDENTITY).build();

  @Test
  public void checkClaims_matchingClaimsPass() throws Exception {
    POLICY.checkClaims(
        Map.of(
            "issuer", ISSUER,
            "identity", IDENTITY,
            "source-repository-uri", "https://github.com/org/repo"));
  }

  @Test
  public void checkClaims_wrongIssuerThrows() {
    var ex =
        assertThrows(
            KeylessVerificationException.class,
            () ->
                POLICY.checkClaims(
                    Map.of("issuer", "https://other.example", "identity", IDENTITY)));
    assertEquals(
        "logged issuer \"https://other.example\" does not match the expected issuer"
            + " \"https://issuer.example\"",
        ex.getMessage());
  }

  @Test
  public void checkClaims_wrongIdentityThrows() {
    var ex =
        assertThrows(
            KeylessVerificationException.class,
            () -> POLICY.checkClaims(Map.of("issuer", ISSUER, "identity", "other@example.com")));
    assertEquals(
        "logged identity \"other@example.com\" does not match the expected identity"
            + " \"user@example.com\"",
        ex.getMessage());
  }

  @Test
  public void checkClaims_missingClaimThrows() {
    var ex =
        assertThrows(
            KeylessVerificationException.class, () -> POLICY.checkClaims(Map.of("issuer", ISSUER)));
    assertEquals("tlog proof has no \"identity\" claim", ex.getMessage());
  }

  @Test
  public void checkClaims_additionalClaimMatchPasses() throws Exception {
    var policy =
        IdentityPolicy.builder()
            .issuer(ISSUER)
            .identity(IDENTITY)
            .putAdditionalClaims("source-repository-ref", "refs/heads/main")
            .build();

    policy.checkClaims(
        Map.of("issuer", ISSUER, "identity", IDENTITY, "source-repository-ref", "refs/heads/main"));
  }

  @Test
  public void checkClaims_additionalClaimMismatchThrows() {
    var policy =
        IdentityPolicy.builder()
            .issuer(ISSUER)
            .identity(IDENTITY)
            .putAdditionalClaims("source-repository-ref", "refs/heads/main")
            .build();

    var ex =
        assertThrows(
            KeylessVerificationException.class,
            () ->
                policy.checkClaims(
                    Map.of(
                        "issuer", ISSUER,
                        "identity", IDENTITY,
                        "source-repository-ref", "refs/heads/dev")));
    assertEquals(
        "logged source-repository-ref \"refs/heads/dev\" does not match the expected"
            + " source-repository-ref \"refs/heads/main\"",
        ex.getMessage());
  }

  @Test
  public void build_reservedAdditionalClaimThrows() {
    for (String reserved : new String[] {"issuer", "identity"}) {
      assertThrows(
          IllegalStateException.class,
          () ->
              IdentityPolicy.builder()
                  .issuer(ISSUER)
                  .identity(IDENTITY)
                  .putAdditionalClaims(reserved, "value")
                  .build(),
          reserved);
    }
  }
}
