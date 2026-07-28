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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.protobuf.ByteString;
import dev.sigstore.oidc.client.FakeOidcClient;
import dev.sigstore.proto.rekor.v2.IdentityRequestV001;
import dev.sigstore.proto.rekor.v2.OidcCredential;
import dev.sigstore.trustroot.Service;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class RekorV2PqcClientHttpTest {
  private static RekorV2PqcClient client;

  @BeforeAll
  public static void setupClient() {
    var rekorService = Service.of(URI.create("http://localhost:3006"), 3);
    client = RekorV2PqcClientHttp.builder().setService(rekorService).build();
  }

  @Test
  public void putEntry() throws Exception {
    var req = createIdentityRequest();
    var proof = client.putEntry(req);

    assertNotNull(proof);
    assertTrue(proof.getLogIndex() >= 0);
    assertNotNull(proof.getCheckpoint());
    assertNotNull(proof.getHashes());
    assertNotNull(proof.getExtra());
    assertTrue(proof.toProofString().startsWith("c2sp.org/tlog-proof@v1"));
  }

  private static IdentityRequestV001 createIdentityRequest() throws Exception {
    String token = FakeOidcClient.getToken();

    var oidc = OidcCredential.newBuilder().setToken(token).build();
    var data = "test identity payload " + UUID.randomUUID();
    var digest = MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));
    var message = ByteString.copyFrom(digest);

    return IdentityRequestV001.newBuilder().setOidc(oidc).setMessage(message).build();
  }
}
