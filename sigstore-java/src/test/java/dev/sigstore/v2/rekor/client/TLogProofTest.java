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

public class TLogProofTest {

  private static TLogProof proofWithExtraLines(String... extraPayloads) {
    var builder = ImmutableTLogProof.builder().logIndex(0).checkpoint("checkpoint\n");
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
  public void parseExtraData_decodesClaims() throws Exception {
    var proof =
        proofWithExtraLines(
            "identity:Zm9vQGJhci5jb20=\n"
                + "issuer:aHR0cDovL2Zha2VvaWRjOjgwODA=\n"
                + "subject:Zm9vQGJhci5jb20=");

    assertEquals(
        Map.of(
            "identity", "foo@bar.com",
            "issuer", "http://fakeoidc:8080",
            "subject", "foo@bar.com"),
        proof.parseExtraData());
  }

  @Test
  public void parseExtraData_moreThanOneExtraLineThrows() {
    var proof = proofWithExtraLines("issuer:YQ==", "identity:Yg==");

    var ex = assertThrows(RekorParseException.class, proof::parseExtraData);
    assertTrue(ex.getMessage().contains("more than one extra line"), ex.getMessage());
  }

  @Test
  public void parseExtraData_lineWithoutColonThrows() {
    var proof = proofWithExtraLines("issuer:YQ==\nnocolon");

    var ex = assertThrows(RekorParseException.class, proof::parseExtraData);
    assertTrue(ex.getMessage().contains("claim line 2"), ex.getMessage());
  }

  @Test
  public void parseExtraData_emptyNameThrows() {
    var proof = proofWithExtraLines(":YQ==");

    var ex = assertThrows(RekorParseException.class, proof::parseExtraData);
    assertTrue(ex.getMessage().contains("claim line 1"), ex.getMessage());
  }

  @Test
  public void parseExtraData_repeatedNameThrows() {
    var proof = proofWithExtraLines("issuer:YQ==\nissuer:Yg==");

    var ex = assertThrows(RekorParseException.class, proof::parseExtraData);
    assertTrue(ex.getMessage().contains("\"issuer\" appears more than once"), ex.getMessage());
  }

  @Test
  public void parseExtraData_invalidBase64Throws() {
    var proof = proofWithExtraLines("issuer:not*base64");

    var ex = assertThrows(RekorParseException.class, proof::parseExtraData);
    assertTrue(ex.getMessage().contains("\"issuer\" is not valid base64"), ex.getMessage());
  }
}
