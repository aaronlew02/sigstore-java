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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.protobuf.ByteString;
import dev.sigstore.KeylessVerificationException;
import dev.sigstore.oidc.client.FakeOidcClient;
import dev.sigstore.proto.rekor.v2.IdentityRequestV001;
import dev.sigstore.proto.rekor.v2.OidcCredential;
import dev.sigstore.trustroot.Service;
import dev.sigstore.v2.bundle.ImmutableBundle;
import dev.sigstore.v2.rekor.client.RekorClient;
import dev.sigstore.v2.rekor.client.RekorClientHttp;
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

public class KeylessVerifierTest {
  private static RekorClient client;

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
    client = RekorClientHttp.builder().setService(rekorService).build();
  }

  @Test
  public void testBuilder_sigstorePublicDefaults() throws Exception {
    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    assertNotNull(verifier);
  }

  @Test
  public void verify_withDigest() throws Exception {
    Assumptions.assumeTrue(isServiceRunning(), "Rekor/OIDC service is not running locally");

    var data = "test identity payload " + UUID.randomUUID();
    var digest = MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));
    var req = createIdentityRequest(digest);
    var proof = client.putEntry(req);
    var bundlePqc = ImmutableBundle.builder().tlogProof(proof).build();

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    var policy =
        IdentityPolicy.builder().issuer("http://fakeoidc:8080").identity("foo@bar.com").build();
    var options = VerificationOptions.builder().identityPolicy(policy).build();

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
    var bundlePqc = ImmutableBundle.builder().tlogProof(proof).build();

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    var policy =
        IdentityPolicy.builder().issuer("http://fakeoidc:8080").identity("foo@bar.com").build();
    var options = VerificationOptions.builder().identityPolicy(policy).build();

    verifier.verify(artifactPath, bundlePqc, options);
  }

  @Test
  public void verify_invalidIdentityThrows() throws Exception {
    Assumptions.assumeTrue(isServiceRunning(), "Rekor/OIDC service is not running locally");

    var data = "test identity payload " + UUID.randomUUID();
    var digest = MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));
    var req = createIdentityRequest(digest);
    var proof = client.putEntry(req);
    var bundlePqc = ImmutableBundle.builder().tlogProof(proof).build();

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    var wrongPolicy =
        IdentityPolicy.builder().issuer("http://fakeoidc:8080").identity("wrong@bar.com").build();
    var wrongOptions = VerificationOptions.builder().identityPolicy(wrongPolicy).build();

    var ex =
        assertThrows(
            KeylessVerificationException.class,
            () -> verifier.verify(digest, bundlePqc, wrongOptions));
    assertTrue(ex.getMessage().contains("expected identity \"wrong@bar.com\""), ex.getMessage());
  }

  @Test
  public void verify_additionalClaimMatches() throws Exception {
    Assumptions.assumeTrue(isServiceRunning(), "Rekor/OIDC service is not running locally");

    var data = "test identity payload " + UUID.randomUUID();
    var digest = MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));
    var req = createIdentityRequest(digest);
    var proof = client.putEntry(req);
    var bundlePqc = ImmutableBundle.builder().tlogProof(proof).build();

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    var policy =
        IdentityPolicy.builder()
            .issuer("http://fakeoidc:8080")
            .identity("foo@bar.com")
            .putAdditionalClaims("subject", "foo@bar.com")
            .build();
    var options = VerificationOptions.builder().identityPolicy(policy).build();

    verifier.verify(digest, bundlePqc, options);
  }

  @Test
  public void verify_additionalClaimMismatchThrows() throws Exception {
    Assumptions.assumeTrue(isServiceRunning(), "Rekor/OIDC service is not running locally");

    var data = "test identity payload " + UUID.randomUUID();
    var digest = MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));
    var req = createIdentityRequest(digest);
    var proof = client.putEntry(req);
    var bundlePqc = ImmutableBundle.builder().tlogProof(proof).build();

    var verifier = KeylessVerifier.builder().sigstorePublicDefaults().build();
    var policy =
        IdentityPolicy.builder()
            .issuer("http://fakeoidc:8080")
            .identity("foo@bar.com")
            .putAdditionalClaims("subject", "wrong@bar.com")
            .build();
    var options = VerificationOptions.builder().identityPolicy(policy).build();

    var ex =
        assertThrows(
            KeylessVerificationException.class, () -> verifier.verify(digest, bundlePqc, options));
    assertTrue(ex.getMessage().contains("expected subject \"wrong@bar.com\""), ex.getMessage());
  }

  private static IdentityRequestV001 createIdentityRequest(byte[] digest) throws Exception {
    String token = FakeOidcClient.getToken();

    var oidc = OidcCredential.newBuilder().setToken(token).build();
    var message = ByteString.copyFrom(digest);

    return IdentityRequestV001.newBuilder().setOidc(oidc).setMessage(message).build();
  }
}
