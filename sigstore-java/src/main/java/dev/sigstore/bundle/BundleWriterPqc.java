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
package dev.sigstore.bundle;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.util.JsonFormat;

class BundleWriterPqc {
  static final JsonFormat.Printer JSON_PRINTER = JsonFormat.printer();

  /**
   * Generates Sigstore PQC Bundle JSON from {@link BundlePqc}.
   *
   * @param bundle PQC keyless bundle.
   * @return Sigstore Bundle in JSON format
   */
  static String writeBundle(BundlePqc bundle) {
    var protoBundle = createBundleBuilder(bundle).build();
    try {
      return JSON_PRINTER.print(protoBundle);
    } catch (InvalidProtocolBufferException e) {
      throw new IllegalArgumentException(
          "Can't serialize PQC signing result to Sigstore Bundle JSON", e);
    }
  }

  /**
   * Generates Sigstore Bundle Builder from {@link BundlePqc}.
   *
   * @param bundle PQC keyless bundle.
   * @return Sigstore Bundle in protobuf builder format
   */
  static dev.sigstore.proto.bundle.v2.Bundle.Builder createBundleBuilder(BundlePqc bundle) {
    var tlogProofProto =
        dev.sigstore.proto.bundle.v2.TlogProof.newBuilder()
            .setProof(ByteString.copyFromUtf8(bundle.getTlogProof().toProofString()))
            .build();

    var verificationMaterialProto =
        dev.sigstore.proto.bundle.v2.VerificationMaterial.newBuilder()
            .setTlogProof(tlogProofProto)
            .build();

    return dev.sigstore.proto.bundle.v2.Bundle.newBuilder()
        .setMediaType(bundle.getMediaType())
        .setVerificationMaterial(verificationMaterialProto);
  }
}
