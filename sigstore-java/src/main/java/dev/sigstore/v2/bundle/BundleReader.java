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

import dev.sigstore.bundle.BundleParseException;
import dev.sigstore.json.ProtoJson;
import dev.sigstore.v2.rekor.client.TLogProof;
import java.io.IOException;
import java.io.Reader;

class BundleReader {

  static Bundle readBundle(Reader jsonReader) throws BundleParseException {
    var protoBundleBuilder = dev.sigstore.proto.bundle.v2.Bundle.newBuilder();
    try {
      ProtoJson.parser().merge(jsonReader, protoBundleBuilder);
    } catch (IOException ioe) {
      throw new BundleParseException("Could not process bundle json", ioe);
    }

    var protoBundle = protoBundleBuilder.build();
    if (!Bundle.BUNDLE_V_2_0.equals(protoBundle.getMediaType())) {
      throw new BundleParseException(
          "Unsupported bundle media type: " + protoBundle.getMediaType());
    }

    if (!protoBundle.hasVerificationMaterial()
        || !protoBundle.getVerificationMaterial().hasTlogProof()) {
      throw new BundleParseException("Could not find tlogProof in verificationMaterial");
    }

    byte[] proofBytes =
        protoBundle.getVerificationMaterial().getTlogProof().getProof().toByteArray();
    TLogProof tlogProof;
    try {
      tlogProof = TLogProof.parse(proofBytes);
    } catch (Exception e) {
      throw new BundleParseException("Failed to parse tlogProof from bundle", e);
    }

    return ImmutableBundle.builder()
        .mediaType(protoBundle.getMediaType())
        .tlogProof(tlogProof)
        .build();
  }
}
