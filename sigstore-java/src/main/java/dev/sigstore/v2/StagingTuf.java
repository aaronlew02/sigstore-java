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

import dev.sigstore.trustroot.tuf.SigstoreTufClient;
import dev.sigstore.tuf.RootProvider;
import java.net.URI;
import java.nio.file.Path;

public final class StagingTuf {

  static final String STAGING_ROOT_RESOURCE = "dev/sigstore/v2/tuf/tuf-root-staging/root.json";

  private StagingTuf() {}

  public static SigstoreTufClient.Builder clientBuilder() {
    return SigstoreTufClient.builder()
        .tufMirror(
            URI.create("https://tuf.v2.sigstage.dev"),
            RootProvider.fromResource(STAGING_ROOT_RESOURCE))
        .tufCacheLocation(
            Path.of(System.getProperty("user.home"))
                .resolve(".sigstore-java")
                .resolve("v2-staging")
                .resolve("root"));
  }
}
