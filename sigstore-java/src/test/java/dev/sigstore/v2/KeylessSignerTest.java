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
import dev.sigstore.testing.matchers.ByteArrayListMatcher;
import dev.sigstore.testkit.annotations.DisabledIfSkipStaging;
import dev.sigstore.v2.bundle.Bundle;
import dev.sigstore.v2.rekor.client.WitnessPolicy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

@DisabledIfSkipStaging
public class KeylessSignerTest {
  @TempDir public static Path testRoot;

  public static List<byte[]> artifactHashes;
  public static List<Path> artifacts;
  public static List<Bundle> signingResults;
  public static KeylessSigner signer;

  @BeforeAll
  public static void setup() throws Exception {
    artifactHashes = new ArrayList<>();
    artifacts = new ArrayList<>();
    signingResults = new ArrayList<>();
    for (int i = 0; i < 2; i++) {
      var artifact = testRoot.resolve("artifact" + i + ".e2e");
      Files.createFile(artifact);
      Files.write(
          artifact, ("some test data " + UUID.randomUUID()).getBytes(StandardCharsets.UTF_8));
      var hash =
          com.google.common.io.Files.asByteSource(artifact.toFile())
              .hash(Hashing.sha256())
              .asBytes();
      artifactHashes.add(hash);
      artifacts.add(artifact);
      signingResults.add(Mockito.mock(Bundle.class));
    }

    Assertions.assertNotEquals(signingResults.get(0), signingResults.get(1));

    signer =
        Mockito.spy(
            KeylessSigner.builder()
                .sigstoreStagingDefaults()
                .witnessPolicy(WitnessPolicy.NONE)
                .build());
    Mockito.doReturn(signingResults.subList(0, 1))
        .when(signer)
        .sign(Mockito.argThat(new ByteArrayListMatcher(artifactHashes.subList(0, 1))));
    Mockito.doReturn(signingResults)
        .when(signer)
        .sign(Mockito.argThat(new ByteArrayListMatcher(artifactHashes)));
  }

  @Test
  public void sign_file() throws Exception {
    Assertions.assertEquals(signingResults.get(0), signer.signFile(artifacts.get(0)));
  }

  @Test
  public void sign_files() throws Exception {
    var signingResultsMap = new HashMap<Path, Bundle>();
    for (int i = 0; i < signingResults.size(); i++) {
      signingResultsMap.put(artifacts.get(i), signingResults.get(i));
    }
    Assertions.assertEquals(signingResultsMap, signer.signFiles(artifacts));
  }

  @Test
  public void sign_digest() throws Exception {
    Assertions.assertEquals(signingResults.get(0), signer.sign(artifactHashes.get(0)));
  }
}
