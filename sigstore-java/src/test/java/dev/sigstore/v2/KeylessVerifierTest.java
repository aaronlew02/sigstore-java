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
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.common.io.Resources;
import dev.sigstore.KeylessVerificationException;
import dev.sigstore.testkit.annotations.DisabledIfSkipStaging;
import dev.sigstore.v2.bundle.Bundle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

@DisabledIfSkipStaging
public class KeylessVerifierTest {
  private static final String ISSUER = "https://accounts.google.com";
  private static final String IDENTITY =
      "untrusted-sa@sigstore-conformance.iam.gserviceaccount.com";
  private static final String SUBJECT = "105144618049248966177";

  private static Path artifact;
  private static byte[] digest;
  private static Bundle bundle;

  @BeforeAll
  public static void loadResources() throws Exception {
    artifact =
        Path.of(Resources.getResource("dev/sigstore/v2/samples/bundles/artifact.txt").toURI());
    digest = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(artifact));
    bundle =
        Bundle.from(
            Path.of(
                Resources.getResource(
                        "dev/sigstore/v2/samples/bundles/bundle-staging.v2.sigstore.json")
                    .toURI()));
  }

  @Test
  public void verify_withDigest() throws Exception {
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();
    var policy = IdentityPolicy.builder().issuer(ISSUER).identity(IDENTITY).build();
    var options = VerificationOptions.builder().identityPolicy(policy).build();

    verifier.verify(digest, bundle, options);
  }

  @Test
  public void verify_withArtifactPath() throws Exception {
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();
    var policy = IdentityPolicy.builder().issuer(ISSUER).identity(IDENTITY).build();
    var options = VerificationOptions.builder().identityPolicy(policy).build();

    verifier.verify(artifact, bundle, options);
  }

  @Test
  public void verify_mismatchedArtifactThrows() throws Exception {
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();
    var policy = IdentityPolicy.builder().issuer(ISSUER).identity(IDENTITY).build();
    var options = VerificationOptions.builder().identityPolicy(policy).build();
    var otherDigest =
        MessageDigest.getInstance("SHA-256")
            .digest("other artifact".getBytes(StandardCharsets.UTF_8));

    var ex =
        assertThrows(
            KeylessVerificationException.class,
            () -> verifier.verify(otherDigest, bundle, options));
    assertEquals("Transparency log inclusion proof could not be verified", ex.getMessage());
    assertEquals("Inclusion proof verification failed", ex.getCause().getMessage());
  }

  @Test
  public void verify_badCheckpointSignatureThrows() throws Exception {
    var badBundle =
        Bundle.from(
            Path.of(
                Resources.getResource(
                        "dev/sigstore/v2/samples/bundles/bundle-with-bad-checkpoint-signature.v2.sigstore.json")
                    .toURI()));
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();
    var policy = IdentityPolicy.builder().issuer(ISSUER).identity(IDENTITY).build();
    var options = VerificationOptions.builder().identityPolicy(policy).build();

    var ex =
        assertThrows(
            KeylessVerificationException.class, () -> verifier.verify(digest, badBundle, options));
    assertEquals("Transparency log inclusion proof could not be verified", ex.getMessage());
    assertEquals(
        "Could not verify checkpoint signature for identity: pqc27-a1.us-east4.rekor.sigstage.dev",
        ex.getCause().getMessage());
  }

  @Test
  public void verify_invalidIdentityThrows() throws Exception {
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();
    var wrongPolicy = IdentityPolicy.builder().issuer(ISSUER).identity("wrong@bar.com").build();
    var wrongOptions = VerificationOptions.builder().identityPolicy(wrongPolicy).build();

    var ex =
        assertThrows(
            KeylessVerificationException.class,
            () -> verifier.verify(digest, bundle, wrongOptions));
    assertTrue(ex.getMessage().contains("expected identity \"wrong@bar.com\""), ex.getMessage());
  }

  @Test
  public void verify_additionalClaimMatches() throws Exception {
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();
    var policy =
        IdentityPolicy.builder()
            .issuer(ISSUER)
            .identity(IDENTITY)
            .putAdditionalClaims("subject", SUBJECT)
            .build();
    var options = VerificationOptions.builder().identityPolicy(policy).build();

    verifier.verify(digest, bundle, options);
  }

  @Test
  public void verify_additionalClaimMismatchThrows() throws Exception {
    var verifier = KeylessVerifier.builder().sigstoreStagingDefaults().build();
    var policy =
        IdentityPolicy.builder()
            .issuer(ISSUER)
            .identity(IDENTITY)
            .putAdditionalClaims("subject", "wrong@bar.com")
            .build();
    var options = VerificationOptions.builder().identityPolicy(policy).build();

    var ex =
        assertThrows(
            KeylessVerificationException.class, () -> verifier.verify(digest, bundle, options));
    assertTrue(ex.getMessage().contains("expected subject \"wrong@bar.com\""), ex.getMessage());
  }
}
