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
package dev.sigstore.oidc.client;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** An OIDC client and token provider for test and prototype environments using fakeoidc. */
public class FakeOidcClient {

  public static final String DEFAULT_OIDC_URL = "http://localhost:8080/token";
  public static final String DEFAULT_ISSUER = "http://fakeoidc:8080";

  public static TokenStringOidcClient.TokenStringProvider newProvider() {
    return newProvider(DEFAULT_OIDC_URL, DEFAULT_ISSUER);
  }

  public static TokenStringOidcClient.TokenStringProvider newProvider(
      String oidcUrl, String issuer) {
    return new TokenStringOidcClient.TokenStringProvider() {
      @Override
      public String getTokenString(Map<String, String> env) throws Exception {
        return getToken(oidcUrl, issuer);
      }

      @Override
      public boolean isEnabled(Map<String, String> env) {
        return true;
      }
    };
  }

  public static OidcClients of() {
    return of(DEFAULT_OIDC_URL, DEFAULT_ISSUER);
  }

  public static OidcClients of(String oidcUrl, String issuer) {
    return OidcClients.of(TokenStringOidcClient.from(newProvider(oidcUrl, issuer)));
  }

  public static String getToken() throws Exception {
    return getToken(DEFAULT_OIDC_URL, DEFAULT_ISSUER);
  }

  public static String getToken(String oidcUrl, String issuer) throws Exception {
    HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();
    URI tokenUri = URI.create(oidcUrl + "?issuer=" + issuer);
    HttpRequest request = HttpRequest.newBuilder().uri(tokenUri).GET().build();
    HttpResponse<String> response =
        client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    if (response.statusCode() != 200) {
      throw new IOException(
          "Failed to obtain test OIDC token from "
              + tokenUri
              + " (status: "
              + response.statusCode()
              + ")");
    }
    return response.body();
  }

  public static OidcToken getOidcToken() throws OidcException {
    return of().getIDToken();
  }

  public static OidcToken getOidcToken(String oidcUrl, String issuer) throws OidcException {
    return of(oidcUrl, issuer).getIDToken();
  }

  public static boolean isServiceRunning() {
    return isServiceRunning(DEFAULT_OIDC_URL, DEFAULT_ISSUER);
  }

  public static boolean isServiceRunning(String oidcUrl, String issuer) {
    try {
      HttpClient client = HttpClient.newHttpClient();
      HttpRequest tokenReq =
          HttpRequest.newBuilder().uri(URI.create(oidcUrl + "?issuer=" + issuer)).GET().build();
      HttpResponse<String> tokenResp =
          client.send(tokenReq, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
      return tokenResp.statusCode() == 200;
    } catch (Exception e) {
      return false;
    }
  }
}
