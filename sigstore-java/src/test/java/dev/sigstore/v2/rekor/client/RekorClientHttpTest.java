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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.protobuf.ByteString;
import dev.sigstore.proto.rekor.v2.IdentityRequestV001;
import dev.sigstore.proto.rekor.v2.OidcCredential;
import dev.sigstore.testkit.annotations.DisabledIfSkipStaging;
import dev.sigstore.testkit.oidc.ConformanceTestingToken;
import dev.sigstore.trustroot.Service;
import dev.sigstore.v2.StagingTuf;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

@DisabledIfSkipStaging
public class RekorClientHttpTest {
  private static RekorClient client;

  @BeforeAll
  public static void setupClient() throws Exception {
    var tufClient = StagingTuf.clientBuilder().build();
    tufClient.update();
    var signingConfig = tufClient.getSigstoreSigningConfig();
    var rekorService = Service.select(signingConfig.getTLogs(), List.of(2)).get();
    client = RekorClientHttp.builder().setService(rekorService).build();
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
    String token = ConformanceTestingToken.getToken();

    var oidc = OidcCredential.newBuilder().setToken(token).build();
    var data = "test identity payload " + UUID.randomUUID();
    var digest = MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));
    var message = ByteString.copyFrom(digest);

    return IdentityRequestV001.newBuilder().setOidc(oidc).setMessage(message).build();
  }
}
