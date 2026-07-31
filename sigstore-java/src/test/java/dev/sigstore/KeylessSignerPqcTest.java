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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import dev.sigstore.VerificationOptionsPqc.OidcTokenIdentity;
import dev.sigstore.bundle.BundlePqc;
import dev.sigstore.oidc.client.FakeOidcClient;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class KeylessSignerPqcTest {

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

  @Test
  public void testBuilder_sigstorePublicDefaults() throws Exception {
    var signer = KeylessSignerPqc.builder().sigstorePublicDefaults().build();
    assertNotNull(signer);
  }

  @Test
  public void testSign_withDigest() throws Exception {
    Assumptions.assumeTrue(isServiceRunning(), "Rekor/OIDC service is not running locally");

    var signer = KeylessSignerPqc.builder().sigstorePublicDefaults().build();
    var data = "test sign digest payload " + UUID.randomUUID();
    var digest = MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));

    BundlePqc bundle = signer.sign(digest);
    assertNotNull(bundle);
    assertEquals(BundlePqc.BUNDLE_V_2_0, bundle.getMediaType());
    assertNotNull(bundle.getTlogProof());

    // Verify using KeylessVerifierPqc
    var verifier = KeylessVerifierPqc.builder().sigstorePublicDefaults().build();
    var identity =
        OidcTokenIdentity.builder().issuer("http://fakeoidc:8080").subject("foo@bar.com").build();
    var options = VerificationOptionsPqc.builder().oidcTokenIdentity(identity).build();

    verifier.verify(digest, bundle, options);
  }

  @Test
  public void testSignFile(@TempDir Path tempDir) throws Exception {
    Assumptions.assumeTrue(isServiceRunning(), "Rekor/OIDC service is not running locally");

    var signer = KeylessSignerPqc.builder().sigstorePublicDefaults().build();
    var data = "test sign file payload " + UUID.randomUUID();
    var artifactPath = tempDir.resolve("artifact.txt");
    Files.writeString(artifactPath, data, StandardCharsets.UTF_8);

    BundlePqc bundle = signer.signFile(artifactPath);
    assertNotNull(bundle);
    assertEquals(BundlePqc.BUNDLE_V_2_0, bundle.getMediaType());
    assertNotNull(bundle.getTlogProof());

    // Verify using KeylessVerifierPqc
    var verifier = KeylessVerifierPqc.builder().sigstorePublicDefaults().build();
    var identity =
        OidcTokenIdentity.builder().issuer("http://fakeoidc:8080").subject("foo@bar.com").build();
    var options = VerificationOptionsPqc.builder().oidcTokenIdentity(identity).build();

    verifier.verify(artifactPath, bundle, options);
  }

  @Test
  public void testSignFiles(@TempDir Path tempDir) throws Exception {
    Assumptions.assumeTrue(isServiceRunning(), "Rekor/OIDC service is not running locally");

    var signer = KeylessSignerPqc.builder().sigstorePublicDefaults().build();
    var file1 = tempDir.resolve("artifact1.txt");
    var file2 = tempDir.resolve("artifact2.txt");
    Files.writeString(file1, "content 1 " + UUID.randomUUID(), StandardCharsets.UTF_8);
    Files.writeString(file2, "content 2 " + UUID.randomUUID(), StandardCharsets.UTF_8);

    var bundlesMap = signer.signFiles(List.of(file1, file2));
    assertNotNull(bundlesMap);
    assertEquals(2, bundlesMap.size());
    assertNotNull(bundlesMap.get(file1));
    assertNotNull(bundlesMap.get(file2));

    var verifier = KeylessVerifierPqc.builder().sigstorePublicDefaults().build();
    var identity =
        OidcTokenIdentity.builder().issuer("http://fakeoidc:8080").subject("foo@bar.com").build();
    var options = VerificationOptionsPqc.builder().oidcTokenIdentity(identity).build();

    verifier.verify(file1, bundlesMap.get(file1), options);
    verifier.verify(file2, bundlesMap.get(file2), options);
  }
}
