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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.sigstore.rekor.client.RekorParseException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class TransparencyLogProofTest {

  private static TransparencyLogProof proofWithExtraLines(String... extraPayloads) {
    var builder = ImmutableTransparencyLogProof.builder().logIndex(0).checkpoint("checkpoint\n");
    for (String payload : extraPayloads) {
      builder.addExtra(payload.getBytes(StandardCharsets.UTF_8));
    }
    return builder.build();
  }

  @Test
  public void parseExtraData_noExtraLine() throws Exception {
    assertEquals(Map.of(), proofWithExtraLines().parseExtraData());
  }

  @Test
  public void parseExtraData_parsesClaims() throws Exception {
    var proof =
        proofWithExtraLines(
            "identity:foo@bar.com\n" + "issuer:http://fakeoidc:8080\n" + "subject:foo@bar.com");

    assertEquals(
        Map.of(
            "identity", "foo@bar.com",
            "issuer", "http://fakeoidc:8080",
            "subject", "foo@bar.com"),
        proof.parseExtraData());
  }

  @Test
  public void parseExtraData_moreThanOneExtraLineThrows() {
    var proof = proofWithExtraLines("issuer:a", "identity:b");

    var ex = assertThrows(RekorParseException.class, proof::parseExtraData);
    assertTrue(ex.getMessage().contains("more than one extra line"), ex.getMessage());
  }

  @Test
  public void parseExtraData_lineWithoutColonThrows() {
    var proof = proofWithExtraLines("issuer:a\nnocolon");

    var ex = assertThrows(RekorParseException.class, proof::parseExtraData);
    assertTrue(ex.getMessage().contains("claim line 2"), ex.getMessage());
  }

  @Test
  public void parseExtraData_emptyNameThrows() {
    var proof = proofWithExtraLines(":a");

    var ex = assertThrows(RekorParseException.class, proof::parseExtraData);
    assertTrue(ex.getMessage().contains("claim line 1"), ex.getMessage());
  }

  @Test
  public void parseExtraData_repeatedNameThrows() {
    var proof = proofWithExtraLines("issuer:a\nissuer:b");

    var ex = assertThrows(RekorParseException.class, proof::parseExtraData);
    assertTrue(ex.getMessage().contains("\"issuer\" appears more than once"), ex.getMessage());
  }
}
