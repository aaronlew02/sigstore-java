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
package dev.sigstore;

import java.util.Optional;
import org.immutables.value.Value.Immutable;

@Immutable(singleton = true)
public interface VerificationOptionsPqc {

  /**
   * The expected OIDC token identity used to construct the transparency log entry for verification.
   */
  Optional<OidcTokenIdentity> getOidcTokenIdentity();

  /** An identity containing the expected subject and issuer for OIDC verification. */
  @Immutable
  interface OidcTokenIdentity {

    /** The expected subject claim from the identity token. */
    String getSubject();

    /** The expected issuer claim from the identity token. */
    String getIssuer();

    static ImmutableOidcTokenIdentity.Builder builder() {
      return ImmutableOidcTokenIdentity.builder();
    }
  }

  static ImmutableVerificationOptionsPqc.Builder builder() {
    return ImmutableVerificationOptionsPqc.builder();
  }

  static VerificationOptionsPqc empty() {
    return ImmutableVerificationOptionsPqc.of();
  }
}
