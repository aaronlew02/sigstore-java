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
import dev.sigstore.json.ProtoJson;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class BundleTest {

  @Test
  void testReadIdentityBundle() throws Exception {
    var url = Resources.getResource("dev/sigstore/v2/samples/bundles/bundle.v2.sigstore.json");
    Bundle bundlePqc;
    try (var reader = new InputStreamReader(url.openStream(), StandardCharsets.UTF_8)) {
      bundlePqc = Bundle.from(reader);
    }

    Assertions.assertEquals(Bundle.BUNDLE_V_2_0, bundlePqc.getMediaType());
    Assertions.assertNotNull(bundlePqc.getTlogProof());
    Assertions.assertEquals(13L, bundlePqc.getTlogProof().getLogIndex());
    Assertions.assertEquals(
        "http://fakeoidc:8080", bundlePqc.getTlogProof().parseExtraData().get("issuer"));
    Assertions.assertEquals(
        "foo@bar.com", bundlePqc.getTlogProof().parseExtraData().get("subject"));
  }

  @Test
  void testRoundTripJsonSerialization() throws Exception {
    var url = Resources.getResource("dev/sigstore/v2/samples/bundles/bundle.v2.sigstore.json");
    Bundle originalBundle;
    try (var reader = new InputStreamReader(url.openStream(), StandardCharsets.UTF_8)) {
      originalBundle = Bundle.from(reader);
    }

    String json = originalBundle.toJson();
    Bundle deserializedBundle = Bundle.from(new StringReader(json));

    Assertions.assertEquals(originalBundle.getMediaType(), deserializedBundle.getMediaType());
    Assertions.assertEquals(
        originalBundle.getTlogProof().getLogIndex(),
        deserializedBundle.getTlogProof().getLogIndex());
    Assertions.assertEquals(
        originalBundle.getTlogProof().parseExtraData(),
        deserializedBundle.getTlogProof().parseExtraData());
  }

  @Test
  void testWriteSetsMessageSignature() throws Exception {
    var url = Resources.getResource("dev/sigstore/v2/samples/bundles/bundle.v2.sigstore.json");
    Bundle bundle;
    try (var reader = new InputStreamReader(url.openStream(), StandardCharsets.UTF_8)) {
      bundle = Bundle.from(reader);
    }

    var protoBundle = dev.sigstore.proto.bundle.v2.Bundle.newBuilder();
    ProtoJson.parser().merge(bundle.toJson(), protoBundle);
    Assertions.assertTrue(protoBundle.hasMessageSignature());
  }

  @Test
  void testInvalidMediaType() {
    String invalidJson = "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\"}";
    var ex =
        Assertions.assertThrows(
            BundleParseException.class, () -> Bundle.from(new StringReader(invalidJson)));
    Assertions.assertTrue(ex.getMessage().contains("Unsupported bundle media type"));
  }

  @Test
  void testMissingTlogProof() {
    String jsonNoProof =
        "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v2.0+json\","
            + "\"verificationMaterial\":{}}";
    var ex =
        Assertions.assertThrows(
            BundleParseException.class, () -> Bundle.from(new StringReader(jsonNoProof)));
    Assertions.assertTrue(ex.getMessage().contains("Could not find tlogProof"));
  }

  @Test
  void testDsseBundleNotSupported() {
    String dsseJson =
        "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v2.0+json\","
            + "\"embeddedData\":{\"payloadType\":\"application/vnd.in-toto+json\","
            + "\"payload\":\"e30=\"}}";
    var ex =
        Assertions.assertThrows(
            BundleParseException.class, () -> Bundle.from(new StringReader(dsseJson)));
    Assertions.assertTrue(ex.getMessage().contains("DSSE bundles are not supported"));
  }
}
