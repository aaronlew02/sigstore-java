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
package dev.sigstore.v2.bundle;

import com.google.common.io.Resources;
import dev.sigstore.bundle.BundleParseException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class BundleReaderTest {
  @Test
  public void readBundle() throws Exception {
    var bundle = readBundle("dev/sigstore/v2/samples/bundles/bundle-staging.v2.sigstore.json");
    Assertions.assertEquals(Bundle.BUNDLE_V_2_0, bundle.getMediaType());
    Assertions.assertNotNull(bundle.getTransparencyLogProof());
  }

  @Test
  public void readBundle_managedKey() {
    var json =
        "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v2.0+json\","
            + "\"verificationMaterial\":{\"transparencyLogProof\":{\"proof\":\"e30=\","
            + "\"signature\":{\"signature\":\"e30=\"}}}}";
    var ex =
        Assertions.assertThrows(
            BundleParseException.class, () -> Bundle.from(new StringReader(json)));
    Assertions.assertEquals("Managed-key bundles are not supported", ex.getMessage());
  }

  private Bundle readBundle(String resourcePath) throws Exception {
    try (var reader =
        new InputStreamReader(
            Resources.getResource(resourcePath).openStream(), StandardCharsets.UTF_8)) {
      return Bundle.from(reader);
    }
  }
}
