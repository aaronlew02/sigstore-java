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

import com.google.common.hash.Hashing;
import com.google.common.io.Resources;
import dev.sigstore.oidc.client.OidcClients;
import dev.sigstore.oidc.client.TokenStringOidcClient;
import dev.sigstore.rekor.client.RekorParseException;
import dev.sigstore.testkit.annotations.DisabledIfSkipStaging;
import dev.sigstore.testkit.oidc.ConformanceTestingToken;
import dev.sigstore.v2.bundle.Bundle;
import dev.sigstore.v2.rekor.client.WitnessPolicy;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class KeylessTest {
  @TempDir public static Path testRoot;

  public static List<byte[]> artifactDigests;

  // TODO: use the distributed staging witness policy when one exists
  private static WitnessPolicy stagingWitnessPolicy;

  private static final OidcClients CONFORMANCE_TOKEN_CLIENT =
      OidcClients.of(TokenStringOidcClient.from(ConformanceTestingToken.newProvider()));
  private static final String ISSUER = "https://accounts.google.com";
  private static final String IDENTITY =
      "untrusted-sa@sigstore-conformance.iam.gserviceaccount.com";

  @BeforeAll
  public static void setupArtifact() throws IOException, RekorParseException {
    stagingWitnessPolicy =
        WitnessPolicy.from(
            Resources.toString(
                Resources.getResource("dev/sigstore/v2/trustroot/staging_witness_policy.txt"),
                StandardCharsets.UTF_8));
    artifactDigests = new ArrayList<>();

    for (int i = 0; i < 2; i++) {
      var artifact = testRoot.resolve("artifact" + i + ".e2e");
      Files.createFile(artifact);
      Files.write(
          artifact, ("some test data " + UUID.randomUUID()).getBytes(StandardCharsets.UTF_8));
      var digest =
          com.google.common.io.Files.asByteSource(artifact.toFile())
              .hash(Hashing.sha256())
              .asBytes();
      artifactDigests.add(digest);
    }
  }

  @Test
  @DisabledIfSkipStaging
  public void sign_staging() throws Exception {
    var signer =
        KeylessSigner.builder()
            .sigstoreStagingDefaults()
            .witnessPolicy(stagingWitnessPolicy)
            .oidcClients(CONFORMANCE_TOKEN_CLIENT)
            .build();
    var results = signer.sign(artifactDigests);
    verifySigningResult(results);

    var verifier =
        KeylessVerifier.builder()
            .sigstoreStagingDefaults()
            .witnessPolicy(stagingWitnessPolicy)
            .build();
    var policy = IdentityPolicy.builder().issuer(ISSUER).identity(IDENTITY).build();
    var options = VerificationOptions.builder().identityPolicy(policy).build();
    for (int i = 0; i < results.size(); i++) {
      verifier.verify(artifactDigests.get(i), results.get(i), options);
      checkBundleSerialization(results.get(i));
    }
  }

  @Test
  @DisabledIfSkipStaging
  public void attest_staging() throws Exception {
    var signer =
        KeylessSigner.builder()
            .sigstoreStagingDefaults()
            .witnessPolicy(stagingWitnessPolicy)
            .oidcClients(CONFORMANCE_TOKEN_CLIENT)
            .build();
    var artifactDigest = artifactDigests.get(0);
    var payload =
        "{\"_type\":\"https://in-toto.io/Statement/v1\","
            + "\"subject\":[{\"name\":\"artifact0.e2e\",\"digest\":{\"sha256\":\""
            + Hex.toHexString(artifactDigest)
            + "\"}}],"
            + "\"predicateType\":\"https://example.com/test-predicate/v1\","
            + "\"predicate\":{}}";
    var result = signer.attest(payload);

    Assertions.assertEquals(
        payload,
        new String(result.getPayload().orElseThrow().getPayload(), StandardCharsets.UTF_8));

    var verifier =
        KeylessVerifier.builder()
            .sigstoreStagingDefaults()
            .witnessPolicy(stagingWitnessPolicy)
            .build();
    var policy = IdentityPolicy.builder().issuer(ISSUER).identity(IDENTITY).build();
    var options = VerificationOptions.builder().identityPolicy(policy).build();
    verifier.verify(artifactDigest, result, options);
    checkBundleSerialization(result);
  }

  private void verifySigningResult(List<Bundle> results) {
    Assertions.assertEquals(artifactDigests.size(), results.size());

    for (var result : results) {
      Assertions.assertEquals(Bundle.BUNDLE_V_2_0, result.getMediaType());
      Assertions.assertNotNull(result.getTransparencyLogProof());
    }
  }

  private void checkBundleSerialization(Bundle bundle) throws Exception {
    var stringFromBundle = bundle.toJson();
    var bundleFromString = Bundle.from(new StringReader(stringFromBundle));
    var stringFromBundle2 = bundleFromString.toJson();
    Assertions.assertEquals(stringFromBundle, stringFromBundle2);
    Assertions.assertEquals(1, StringUtils.countMatches(stringFromBundle, "mediaType"));
    Assertions.assertTrue(
        stringFromBundle.contains("\"mediaType\": \"" + Bundle.BUNDLE_V_2_0 + "\""));
  }
}
