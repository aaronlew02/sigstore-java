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
package dev.sigstore.rekor.v3.client;

import dev.sigstore.proto.rekor.v2.IdentityRequestV001;
import dev.sigstore.rekor.client.RekorParseException;
import java.io.IOException;

/** A client to communicate with a rekor v3 service instance. */
public interface RekorV2PqcClient {
  /**
   * Put a new identity entry on the Rekor log.
   *
   * @param identityRequest the request to send to rekor
   * @return a {@link TLogProof} representing the transparency log proof
   */
  TLogProof putEntry(IdentityRequestV001 identityRequest) throws IOException, RekorParseException;
}
