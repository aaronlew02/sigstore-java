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

import dev.sigstore.rekor.v3.client.TLogProof;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.immutables.value.Value.Default;
import org.immutables.value.Value.Immutable;

/**
 * A representation of sigstore PQC signing materials. See <a
 * href="https://github.com/sigstore/protobuf-specs/pull/898">protobuf-specs #898</a>
 */
@Immutable
public abstract class BundlePqc {

  public static final String BUNDLE_V_2_0 = "application/vnd.dev.sigstore.bundle.v2.0+json";

  /** The bundle version */
  @Default
  public String getMediaType() {
    return BUNDLE_V_2_0;
  }

  /** The entry in the rekor transparency log. */
  public abstract TLogProof getTlogProof();

  /** Read a json formatted bundle. */
  public static BundlePqc from(Reader bundleJson) throws BundleParseException {
    return BundleReaderPqc.readBundle(bundleJson);
  }

  /** Read a json formatted bundle from a file. */
  public static BundlePqc from(Path file, Charset cs) throws BundleParseException, IOException {
    return BundleReaderPqc.readBundle(Files.newBufferedReader(file, cs));
  }

  /** Read a json formatted bundle from a file. */
  public static BundlePqc from(Path file) throws BundleParseException, IOException {
    return from(file, StandardCharsets.UTF_8);
  }

  public String toJson() {
    return BundleWriterPqc.writeBundle(this);
  }
}
