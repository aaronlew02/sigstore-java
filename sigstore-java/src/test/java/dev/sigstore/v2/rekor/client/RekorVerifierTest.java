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
package dev.sigstore.v2.rekor.client;

import com.google.protobuf.ByteString;
import dev.sigstore.oidc.client.FakeOidcClient;
import dev.sigstore.proto.rekor.v2.IdentityRequestV001;
import dev.sigstore.proto.rekor.v2.OidcCredential;
import dev.sigstore.trustroot.Service;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class RekorVerifierTest {
  private static RekorClient client;

  private static boolean isServiceRunning() {
    if (!FakeOidcClient.isServiceRunning()) {
      return false;
    }
    try {
      HttpClient httpClient = HttpClient.newHttpClient();
      HttpRequest rekorHealthReq =
          HttpRequest.newBuilder().uri(URI.create("http://localhost:3006/healthz")).GET().build();
      HttpResponse<String> rekorHealthResp =
          httpClient.send(rekorHealthReq, BodyHandlers.ofString());
      return rekorHealthResp.statusCode() == 200;
    } catch (Exception e) {
      return false;
    }
  }

  @BeforeAll
  public static void setupClient() {
    Assumptions.assumeTrue(isServiceRunning(), "Rekor/OIDC service is not running locally");

    var rekorService = Service.of(URI.create("http://localhost:3006"), 3);
    client = RekorClientHttp.builder().setService(rekorService).build();
  }

  @Test
  public void verifyProof() throws Exception {
    var req = createIdentityRequest();
    var proof = client.putEntry(req);

    // Compute leaf hash
    byte[] leafHash = computeLeafHash(req.getMessage(), proof);

    // Load local ML-DSA Public Key from rekor-tiles
    String pemStr =
        Files.readString(
            Paths.get("/Users/aaronlew/rekor-tiles/tests/testdata/pki/mldsa-pub-key.pem"));

    // Strip PEM headers
    pemStr =
        pemStr
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
    byte[] pubKeyBytes = Base64.getDecoder().decode(pemStr);

    X509EncodedKeySpec spec = new X509EncodedKeySpec(pubKeyBytes);

    Security.addProvider(new BouncyCastleProvider());
    PublicKey pubKey = KeyFactory.getInstance("ML-DSA", "BC").generatePublic(spec);

    RekorVerifier verifier = RekorVerifier.newRekorVerifier("rekor-local", pubKey);
    verifier.verifyProof(proof, leafHash);
  }

  @Test
  public void verifyProofWithWitnessPolicy() throws Exception {
    var req = createIdentityRequest();
    var proof = client.putEntry(req);

    // Compute leaf hash
    byte[] leafHash = computeLeafHash(req.getMessage(), proof);

    // Load local ML-DSA Public Key from rekor-tiles
    String pemStr =
        Files.readString(
            Paths.get("/Users/aaronlew/rekor-tiles/tests/testdata/pki/mldsa-pub-key.pem"));

    pemStr =
        pemStr
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
    byte[] pubKeyBytes = Base64.getDecoder().decode(pemStr);

    X509EncodedKeySpec spec = new X509EncodedKeySpec(pubKeyBytes);

    Security.addProvider(new BouncyCastleProvider());
    PublicKey pubKey = KeyFactory.getInstance("ML-DSA", "BC").generatePublic(spec);

    String witnessPolicyStr =
        Files.readString(
            Paths.get("/Users/aaronlew/rekor-tiles/tests/testdata/witness/mldsa-policy.yaml"));

    WitnessPolicy witnessPolicy = WitnessPolicy.from(witnessPolicyStr);

    RekorVerifier verifier = RekorVerifier.newRekorVerifier("rekor-local", pubKey, witnessPolicy);
    verifier.verifyProof(proof, leafHash);
  }

  private static IdentityRequestV001 createIdentityRequest() throws Exception {
    String token = FakeOidcClient.getToken();

    var oidc = OidcCredential.newBuilder().setToken(token).build();

    var data = "test identity payload " + UUID.randomUUID();
    var digest = MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));
    var message = ByteString.copyFrom(digest);

    return IdentityRequestV001.newBuilder().setOidc(oidc).setMessage(message).build();
  }

  private static byte[] computeLeafHash(ByteString message, TLogProof proof) throws Exception {
    byte[] msgBytes = message.toByteArray();
    byte[] msgHash = MessageDigest.getInstance("SHA-256").digest(msgBytes);
    byte[] rootHash =
        MessageDigest.getInstance("SHA-256")
            .digest("http://fakeoidc:8080".getBytes(StandardCharsets.UTF_8));
    var claims = proof.getExtraAsMap();
    List<String> sortedKeys = new ArrayList<>(claims.keySet());
    Collections.sort(sortedKeys);
    ByteArrayOutputStream leafOs = new ByteArrayOutputStream();
    leafOs.write(0x01); // LeafVersionV1
    leafOs.write(rootHash);
    leafOs.write(msgHash);
    for (String key : sortedKeys) {
      String val = claims.get(key);
      byte[] kHash =
          MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8));
      byte[] vHash =
          MessageDigest.getInstance("SHA-256").digest(val.getBytes(StandardCharsets.UTF_8));
      byte[] kDoubleHash = MessageDigest.getInstance("SHA-256").digest(kHash);
      byte[] vDoubleHash = MessageDigest.getInstance("SHA-256").digest(vHash);
      leafOs.write(kDoubleHash);
      leafOs.write(vDoubleHash);
    }

    leafOs.write(new byte[32]); // receipt digest block (all zeros)
    ByteArrayOutputStream finalOs = new ByteArrayOutputStream();
    finalOs.write(0x00); // RFC6962 Leaf prefix
    finalOs.write(leafOs.toByteArray());
    byte[] leafHash = MessageDigest.getInstance("SHA-256").digest(finalOs.toByteArray());
    return leafHash;
  }
}
