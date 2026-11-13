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

import com.google.common.base.Preconditions;
import dev.sigstore.UnsupportedAlgorithmException;
import dev.sigstore.merkle.InclusionProofVerificationException;
import dev.sigstore.merkle.InclusionProofVerifier;
import dev.sigstore.rekor.client.Checkpoints;
import dev.sigstore.rekor.client.RekorEntry.Checkpoint;
import dev.sigstore.rekor.client.RekorEntry.CheckpointSignature;
import dev.sigstore.rekor.client.RekorParseException;
import dev.sigstore.rekor.client.RekorVerificationException;
import dev.sigstore.v2.AlgorithmRegistry;
import dev.sigstore.v2.encryption.signers.Verifiers;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/** Verifier for Rekor V2 PQC entries based on the c2sp.org/tlog-proof@v1 format. */
public class RekorVerifier {

  private final List<VerifierKey> logKeys;
  private final WitnessPolicy witnessPolicy;

  public static RekorVerifier newRekorVerifier(
      List<VerifierKey> logKeys, WitnessPolicy witnessPolicy) {
    return new RekorVerifier(logKeys, witnessPolicy);
  }

  private RekorVerifier(List<VerifierKey> logKeys, WitnessPolicy witnessPolicy) {
    Preconditions.checkArgument(!logKeys.isEmpty(), "logKeys must not be empty");
    this.logKeys = List.copyOf(logKeys);
    this.witnessPolicy = Preconditions.checkNotNull(witnessPolicy, "witnessPolicy must be set");
  }

  /**
   * Verifies the inclusion proof and checkpoint signature of a TransparencyLogProof.
   *
   * @param proof The TransparencyLogProof returned by the log.
   * @param leafHash The computed leaf hash (with 0x00{32} receipt digest, per spec).
   * @throws RekorVerificationException if verification fails.
   */
  public void verifyProof(TransparencyLogProof proof, byte[] leafHash)
      throws RekorVerificationException {
    Checkpoint parsedCheckpoint;
    try {
      parsedCheckpoint = Checkpoints.from(proof.getCheckpoint());
    } catch (RekorParseException ex) {
      throw new RekorVerificationException(
          "Could not parse checkpoint from TransparencyLogProof", ex);
    }

    verifyCheckpoint(parsedCheckpoint);
    verifyInclusionProof(proof, parsedCheckpoint, leafHash);
  }

  private void verifyInclusionProof(
      TransparencyLogProof proof, Checkpoint checkpoint, byte[] leafHash)
      throws RekorVerificationException {
    long treeSize = checkpoint.getSize();
    byte[] rootHash = Base64.getDecoder().decode(checkpoint.getBase64Hash());

    try {
      InclusionProofVerifier.verify(
          leafHash, proof.getLogIndex(), treeSize, proof.getHashes(), rootHash);
    } catch (InclusionProofVerificationException e) {
      throw new RekorVerificationException("Inclusion proof verification failed", e);
    }
  }

  private void verifyCheckpoint(Checkpoint checkpoint) throws RekorVerificationException {
    String origin = checkpoint.getOrigin();
    List<VerifierKey> originLogKeys =
        logKeys.stream().filter(key -> key.getName().equals(origin)).collect(Collectors.toList());
    if (originLogKeys.isEmpty()) {
      throw new RekorVerificationException("Checkpoint origin is not a trusted log: " + origin);
    }

    boolean logSigVerified = false;
    Set<String> verifiedWitnesses = new HashSet<>();

    for (CheckpointSignature checkpointSignature : checkpoint.getSignatures()) {
      Optional<VerifierKey> logKey =
          originLogKeys.stream().filter(key -> matches(key, checkpointSignature)).findFirst();
      if (logKey.isPresent()) {
        verifySignature(logKey.get().getPublicKey(), checkpointSignature, checkpoint);
        logSigVerified = true;
        continue;
      }
      for (Map.Entry<String, VerifierKey> witness :
          witnessPolicy.getWitnessVerifierKeys().entrySet()) {
        if (matches(witness.getValue(), checkpointSignature)) {
          verifySignature(witness.getValue().getPublicKey(), checkpointSignature, checkpoint);
          verifiedWitnesses.add(witness.getKey());
        }
      }
    }

    if (!logSigVerified) {
      throw new RekorVerificationException(
          "Checkpoint is missing valid signature from log: " + origin);
    }

    if (!witnessPolicy.isSatisfied(verifiedWitnesses)) {
      throw new RekorVerificationException(
          "Witness policy not satisfied. Verified witnesses: " + verifiedWitnesses);
    }
  }

  private static boolean matches(VerifierKey key, CheckpointSignature checkpointSignature) {
    return key.getName().equals(checkpointSignature.getIdentity())
        && Arrays.equals(key.getKeyId(), checkpointSignature.getKeyHint());
  }

  private void verifySignature(
      PublicKey publicKey, CheckpointSignature checkpointSignature, Checkpoint checkpoint)
      throws RekorVerificationException {
    byte[] sigWithTimestamp = checkpointSignature.getSignature();

    if (sigWithTimestamp.length < 8) {
      throw new RekorVerificationException(
          "Checkpoint signature too short for ML-DSA timestamp: "
              + checkpointSignature.getIdentity());
    }

    long timestamp = ByteBuffer.wrap(sigWithTimestamp, 0, 8).getLong();
    byte[] rawSignature = Arrays.copyOfRange(sigWithTimestamp, 8, sigWithTimestamp.length);

    try {
      AlgorithmRegistry.getSigningAlgorithm(publicKey);
    } catch (UnsupportedAlgorithmException e) {
      throw new RekorVerificationException(
          "Unsupported key algorithm for checkpoint signature for identity: "
              + checkpointSignature.getIdentity(),
          e);
    }

    try {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      baos.write("subtree/v1\n\0".getBytes(StandardCharsets.UTF_8));

      byte[] originBytes = checkpointSignature.getIdentity().getBytes(StandardCharsets.UTF_8);
      baos.write(originBytes.length);
      baos.write(originBytes);

      baos.write(ByteBuffer.allocate(8).putLong(timestamp).array());

      byte[] logOriginBytes = checkpoint.getOrigin().getBytes(StandardCharsets.UTF_8);
      baos.write(logOriginBytes.length);
      baos.write(logOriginBytes);

      baos.write(ByteBuffer.allocate(8).putLong(0L).array());
      baos.write(ByteBuffer.allocate(8).putLong(checkpoint.getSize()).array());
      baos.write(Base64.getDecoder().decode(checkpoint.getBase64Hash()));

      byte[] signedMsg = baos.toByteArray();

      if (!Verifiers.newVerifier(publicKey).verify(signedMsg, rawSignature)) {
        throw new RekorVerificationException(
            "Checkpoint signature invalid for identity: " + checkpointSignature.getIdentity());
      }
    } catch (Exception ex) {
      throw new RekorVerificationException(
          "Could not verify checkpoint signature for identity: "
              + checkpointSignature.getIdentity(),
          ex);
    }
  }
}
