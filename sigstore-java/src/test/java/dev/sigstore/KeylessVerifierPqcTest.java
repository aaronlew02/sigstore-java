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
package dev.sigstore;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.protobuf.ByteString;
import dev.sigstore.VerificationOptionsPqc.OidcTokenIdentity;
import dev.sigstore.bundle.ImmutableBundlePqc;
import dev.sigstore.oidc.client.FakeOidcClient;
import dev.sigstore.proto.rekor.v2.IdentityRequestV001;
import dev.sigstore.proto.rekor.v2.OidcCredential;
import dev.sigstore.rekor.v3.client.RekorV2PqcClient;
import dev.sigstore.rekor.v3.client.RekorV2PqcClientHttp;
import dev.sigstore.rekor.v3.client.TLogProof;
import dev.sigstore.trustroot.Service;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.UUID;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class KeylessVerifierPqcTest {
  private static RekorV2PqcClient client;

  private static boolean isServiceRunning() {
    if (!FakeOidcClient.isServiceRunning()) {
      return false;
    }
    try {
      HttpClient httpClient = HttpClient.newHttpClient();
      HttpRequest rekorHealthReq =
          HttpRequest.newBuilder().uri(URI.create("http://localhost:3006/healthz")).GET().build();
      HttpResponse<String> rekorHealthResp =
          httpClient.send(rekorHealthReq, BodyHandlers.ofString());
      return rekorHealthResp.statusCode() == 200;
    } catch (Exception e) {
      return false;
    }
  }

  @BeforeAll
  public static void setupClient() {
    var rekorService = Service.of(URI.create("http://localhost:3006"), 3);
    client = RekorV2PqcClientHttp.builder().setService(rekorService).build();
  }

  @Test
  public void testBuilder_sigstorePublicDefaults() throws Exception {
    var verifier = KeylessVerifierPqc.builder().sigstorePublicDefaults().build();
    assertNotNull(verifier);
  }

  @Test
  public void testVerify_missingOidcIdentityThrows() throws Exception {
    var verifier = KeylessVerifierPqc.builder().sigstorePublicDefaults().build();
    var testProof =
        TLogProof.parse(
            "c2sp.org/tlog-proof@v1\nindex 1\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n\ncheckpoint"
                .getBytes(StandardCharsets.UTF_8));
    var bundlePqc = ImmutableBundlePqc.builder().tlogProof(testProof).build();

    assertThrows(
        KeylessVerificationException.class,
        () -> verifier.verify(new byte[32], bundlePqc, VerificationOptionsPqc.empty()));
  }

  @Test
  public void verify_withDigest() throws Exception {
    Assumptions.assumeTrue(isServiceRunning(), "Rekor/OIDC service is not running locally");

    var data = "test identity payload " + UUID.randomUUID();
    var digest = MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));
    var req = createIdentityRequest(digest);
    var proof = client.putEntry(req);
    var bundlePqc = ImmutableBundlePqc.builder().tlogProof(proof).build();

    var verifier = KeylessVerifierPqc.builder().sigstorePublicDefaults().build();
    var identity =
        OidcTokenIdentity.builder().issuer("http://fakeoidc:8080").subject("foo@bar.com").build();
    var options = VerificationOptionsPqc.builder().oidcTokenIdentity(identity).build();

    verifier.verify(digest, bundlePqc, options);
  }

  @Test
  public void verify_withArtifactPath(@TempDir Path tempDir) throws Exception {
    Assumptions.assumeTrue(isServiceRunning(), "Rekor/OIDC service is not running locally");

    var data = "test identity payload " + UUID.randomUUID();
    var artifactPath = tempDir.resolve("artifact.txt");
    Files.writeString(artifactPath, data, StandardCharsets.UTF_8);

    var digest = MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));
    var req = createIdentityRequest(digest);
    var proof = client.putEntry(req);
    var bundlePqc = ImmutableBundlePqc.builder().tlogProof(proof).build();

    var verifier = KeylessVerifierPqc.builder().sigstorePublicDefaults().build();
    var identity =
        OidcTokenIdentity.builder().issuer("http://fakeoidc:8080").subject("foo@bar.com").build();
    var options = VerificationOptionsPqc.builder().oidcTokenIdentity(identity).build();

    verifier.verify(artifactPath, bundlePqc, options);
  }

  @Test
  public void verify_invalidIdentityThrows() throws Exception {
    Assumptions.assumeTrue(isServiceRunning(), "Rekor/OIDC service is not running locally");

    var data = "test identity payload " + UUID.randomUUID();
    var digest = MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));
    var req = createIdentityRequest(digest);
    var proof = client.putEntry(req);
    var bundlePqc = ImmutableBundlePqc.builder().tlogProof(proof).build();

    var verifier = KeylessVerifierPqc.builder().sigstorePublicDefaults().build();
    var wrongIdentity =
        OidcTokenIdentity.builder().issuer("http://fakeoidc:8080").subject("wrong@bar.com").build();
    var wrongOptions = VerificationOptionsPqc.builder().oidcTokenIdentity(wrongIdentity).build();

    assertThrows(
        KeylessVerificationException.class, () -> verifier.verify(digest, bundlePqc, wrongOptions));
  }

  private static IdentityRequestV001 createIdentityRequest(byte[] digest) throws Exception {
    String token = FakeOidcClient.getToken();

    var oidc = OidcCredential.newBuilder().setToken(token).build();
    var message = ByteString.copyFrom(digest);

    return IdentityRequestV001.newBuilder().setOidc(oidc).setMessage(message).build();
  }
}
