/*
 * Copyright 2017-2021 Slawomir Jaranowski
 * Portions Copyright 2017-2018 Wren Security.
 * Portions Copyright 2019 Danny van Heumen
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

package org.simplify4u.plugins.pgp;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Optional;
import javax.inject.Named;
import javax.inject.Singleton;

import io.vavr.control.Try;
import org.apache.maven.artifact.Artifact;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.simplify4u.plugins.keyserver.PGPKeyNotFound;
import org.simplify4u.plugins.keyserver.PGPKeysCache;
import org.simplify4u.plugins.utils.HexUtils;

/**
 * Utilities for PGP Signature class.
 */
@Named
@Singleton
public class SignatureUtils {

    /**
     * Check PGP signature for bad algorithms.
     *
     * @param hashAlgorithm PGP signature hashAlgorithm
     *
     * @return Returns null if no bad algorithms used, or algorithm name if used.
     */
    public String checkWeakHashAlgorithm(int hashAlgorithm) {
        switch (hashAlgorithm) {
            case HashAlgorithmTags.MD5:
                return "MD5";
            case HashAlgorithmTags.DOUBLE_SHA:
                return "double-width SHA";
            case HashAlgorithmTags.MD2:
                return "MD2";
            case HashAlgorithmTags.TIGER_192:
                return "TIGER/192";
            case HashAlgorithmTags.HAVAL_5_160:
                return "HAVAL (5 pass, 160-bit)";
            case HashAlgorithmTags.SHA224:
                return "SHA-224";
            case HashAlgorithmTags.SHA1:
                // fallthrough
            case HashAlgorithmTags.RIPEMD160:
                // fallthrough
            case HashAlgorithmTags.SHA256:
                // fallthrough
            case HashAlgorithmTags.SHA384:
                // fallthrough
            case HashAlgorithmTags.SHA512:
                return null;
            default:
                throw new UnsupportedOperationException("Unknown hash algorithm value encountered: "
                        + hashAlgorithm);
        }
    }

    /**
     * Load PGPSignature from input stream.
     *
     * @param input the input stream having PGPSignature content
     *
     * @return Returns the (first) read PGP signature.
     *
     * @throws SignatureException In case of failure loading signature.
     */
    public PGPSignature loadSignature(InputStream input) throws SignatureException {

        try {
            InputStream sigInputStream = PGPUtil.getDecoderStream(input);
            PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(sigInputStream, new BcKeyFingerprintCalculator());

            Object nextObject;
            while ((nextObject = pgpObjectFactory.nextObject()) != null) {

                if (nextObject instanceof PGPSignatureList) {
                    return ((PGPSignatureList) nextObject).get(0);
                }

                if (nextObject instanceof PGPCompressedData) {
                    // next read content of compressed message
                    pgpObjectFactory = new PGPObjectFactory(((PGPCompressedData) nextObject).getDataStream(),
                            new BcKeyFingerprintCalculator());
                }

                if (nextObject instanceof PGPLiteralData) {
                    InputStream dataStream = ((PGPLiteralData) nextObject).getDataStream();
                    byte[] buf = new byte[8192];
                    while (dataStream.read(buf) > 0) {
                        // we must read whole packet in order to proper input stream shift
                    }
                }
            }
        } catch (IOException | PGPException e) {
            throw new SignatureException(e.getMessage(), e);
        }

        throw new SignatureException("PGP signature not found.");
    }

    /**
     * Load PGPSignature from file.
     *
     * @param file the file having PGPSignature content
     *
     * @return Returns the (first) read PGP signature.
     *
     * @throws SignatureException In case of failure loading signature.
     * @throws IOException           In case of IO failures.
     */
    public PGPSignature loadSignature(File file) throws IOException, SignatureException {
        try (InputStream in = new FileInputStream(file)) {
            return loadSignature(in);
        }
    }

    /**
     * Read the content of a file into the PGP signature instance (for verification).
     *
     * @param signature the PGP signature instance. The instance is expected to be initialized.
     * @param file      the file to read
     *
     * @throws IOException In case of failure to open the file or failure while reading its content.
     */
    public void readFileContentInto(final PGPSignature signature, final File file) throws IOException {
        try (InputStream inArtifact = new BufferedInputStream(new FileInputStream(file))) {
            byte[] buf = new byte[8192];
            int t;
            while ((t = inArtifact.read(buf)) >= 0) {
                signature.update(buf, 0, t);
            }
        }
    }

    /**
     * Retrieve Key Id from signature ISSUER_FINGERPRINT subpackage or standard keyId.
     *
     * @param signature the PGP signature instance
     *
     * @return Returns the keyId from signature
     *
     * @throws SignatureException In case of problem with signature data
     */
    public KeyId retrieveKeyId(PGPSignature signature) throws SignatureException {

        Optional<PGPSignatureSubpacketVector> hashedSubPackets = Optional
                .ofNullable(signature.getHashedSubPackets());

        Optional<PGPSignatureSubpacketVector> unHashedSubPackets = Optional
                .ofNullable(signature.getUnhashedSubPackets());

        // more of time issuerFingerprint is in hashedSubPackets
        Optional<IssuerFingerprint> issuerFingerprint = hashedSubPackets
                .map(PGPSignatureSubpacketVector::getIssuerFingerprint);

        if (!issuerFingerprint.isPresent()) {
            issuerFingerprint = unHashedSubPackets.map(PGPSignatureSubpacketVector::getIssuerFingerprint);
        }

        // more of time issuerKeyId is in unHashedSubPackets
        // getIssuerKeyID return 0 (zero) if subpackage not exist
        Optional<Long> issuerKeyId = unHashedSubPackets
                .map(PGPSignatureSubpacketVector::getIssuerKeyID)
                .filter(id -> id != 0L);


        if (!issuerKeyId.isPresent()) {
            issuerKeyId = hashedSubPackets
                    .map(PGPSignatureSubpacketVector::getIssuerKeyID)
                    .filter(id -> id != 0L);
        }

        // test issuerKeyId package and keyId form signature
        if (issuerKeyId.isPresent() && signature.getKeyID() != issuerKeyId.get()) {
            throw new SignatureException(
                    String.format("Signature KeyID 0x%016X is not equals to IssuerKeyID 0x%016X",
                            signature.getKeyID(), issuerKeyId.get()));
        }

        // from RFC
        // If the version of the issuing key is 4 and an Issuer subpacket is also included in the signature,
        // the key ID of the Issuer subpacket MUST match the low 64 bits of the fingerprint.
        if (issuerKeyId.isPresent() && issuerFingerprint.isPresent() && issuerFingerprint.get().getKeyVersion() == 4) {
            byte[] bKey = new byte[8];
            byte[] fingerprint = issuerFingerprint.get().getFingerprint();
            System.arraycopy(fingerprint, fingerprint.length - 8, bKey, 0, 8);
            BigInteger bigInteger = new BigInteger(bKey);
            if (bigInteger.longValue() != issuerKeyId.get()) {
                throw new SignatureException(
                        String.format("Signature IssuerFingerprint 0x%s not contains IssuerKeyID 0x%016X",
                                HexUtils.fingerprintToString(fingerprint), issuerKeyId.get()));
            }
        }

        KeyId keyId;
        if (issuerFingerprint.isPresent()) {
            keyId = KeyId.from(issuerFingerprint.get().getFingerprint());
        } else if (issuerKeyId.isPresent()) {
            keyId = KeyId.from(issuerKeyId.get());
        } else {
            keyId = KeyId.from(signature.getKeyID());
        }

        return keyId;
    }

    /**
     * Create {@link SignatureCheckResult} contains data about artifact, signature, public key used to verify and
     * verification status.
     *
     * @param artifact    The artifact to check signature
     * @param artifactAsc The artifact contains signature
     * @param cache       PGP cache for access public key
     *
     * @return check verification result
     */
    public SignatureCheckResult checkSignature(Artifact artifact, Artifact artifactAsc, PGPKeysCache cache) {

        SignatureCheckResult.SignatureCheckResultBuilder signatureCheckResultBuilder = SignatureCheckResult.builder();

        signatureCheckResultBuilder.artifact(ArtifactInfo.builder()
                .groupId(artifact.getGroupId())
                .artifactId(artifact.getArtifactId())
                .type(artifact.getType())
                .classifier(artifact.getClassifier())
                .version(artifact.getVersion())
                .build());

        if (!artifact.isResolved()) {
            return signatureCheckResultBuilder.status(SignatureStatus.ARTIFACT_NOT_RESOLVED).build();
        }

        if (artifactAsc == null || !artifactAsc.isResolved()) {
            return signatureCheckResultBuilder.status(SignatureStatus.SIGNATURE_NOT_RESOLVED).build();
        }

        PGPSignature signature = Try.of(() -> loadSignature(artifactAsc.getFile()))
                .onFailure(e ->
                        signatureCheckResultBuilder.errorCause(e).status(SignatureStatus.SIGNATURE_ERROR))
                .getOrNull();

        if (signature == null) {
            return signatureCheckResultBuilder.build();
        }

        KeyId keyId = Try.of(() -> retrieveKeyId(signature))
                .onFailure(e ->
                        signatureCheckResultBuilder.errorCause(e).status(SignatureStatus.SIGNATURE_ERROR))
                .getOrNull();

        if (keyId == null) {
            return signatureCheckResultBuilder.build();
        }

        signatureCheckResultBuilder.signature(
                SignatureInfo.builder()
                        .hashAlgorithm(signature.getHashAlgorithm())
                        .keyAlgorithm(signature.getKeyAlgorithm())
                        .date(signature.getCreationTime())
                        .keyId(keyId)
                        .version(signature.getVersion())
                        .build());

        PGPPublicKeyRing publicKeys = Try.of(() -> cache.getKeyRing(keyId))
                .onFailure(e -> signatureCheckResultBuilder.errorCause(e).status(SignatureStatus.ERROR))
                .onFailure(PGPKeyNotFound.class, e -> signatureCheckResultBuilder.status(SignatureStatus.KEY_NOT_FOUND))
                .getOrNull();

        signatureCheckResultBuilder.keyShowUrl(cache.getUrlForShowKey(keyId));

        if (publicKeys == null) {
            return signatureCheckResultBuilder.build();
        }

        PGPPublicKey publicKey = keyId.getKeyFromRing(publicKeys);

        signatureCheckResultBuilder.key(KeyInfo.builder()
                .fingerprint(new KeyFingerprint(publicKey.getFingerprint()))
                .master(PublicKeyUtils.getMasterKey(publicKey, publicKeys)
                        .map(PGPPublicKey::getFingerprint)
                        .map(KeyFingerprint::new)
                        .orElse(null))
                .uids(PublicKeyUtils.getUserIDs(publicKey, publicKeys))
                .version(publicKey.getVersion())
                .algorithm(publicKey.getAlgorithm())
                .bits(publicKey.getBitStrength())
                .date(publicKey.getCreationTime())
                .build());

        Boolean verifyStatus = Try.of(() -> {
            signature.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
            readFileContentInto(signature, artifact.getFile());
            return signature.verify();
        }).onFailure(e -> signatureCheckResultBuilder.errorCause(e).status(SignatureStatus.ERROR))
                .getOrNull();

        if (verifyStatus == null) {
            return signatureCheckResultBuilder.build();
        }

        return signatureCheckResultBuilder
                .status(Boolean.TRUE.equals(verifyStatus)
                        ? SignatureStatus.SIGNATURE_VALID : SignatureStatus.SIGNATURE_INVALID)
                .build();
    }

    /**
     * Map Public-Key algorithms id to name
     *
     * @param keyAlgorithm key algorithm id
     *
     * @return key algorithm name
     *
     * @throws UnsupportedOperationException if algorithm is is not known
     */
    public String keyAlgorithmName(int keyAlgorithm) {
        switch (keyAlgorithm) {
            case PublicKeyAlgorithmTags.RSA_GENERAL:
                return "RSA (Encrypt or Sign)";
            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
                return "RSA Encrypt-Only";
            case PublicKeyAlgorithmTags.RSA_SIGN:
                return "RSA Sign-Only";
            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
                return "Elgamal (Encrypt-Only)";
            case PublicKeyAlgorithmTags.DSA:
                return "DSA (Digital Signature Algorithm)";
            case PublicKeyAlgorithmTags.ECDH:
                return "Elliptic Curve";
            case PublicKeyAlgorithmTags.ECDSA:
                return "Elliptic Curve Digital Signature";
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
                return "Elgamal (Encrypt or Sign)";
            case PublicKeyAlgorithmTags.DIFFIE_HELLMAN:
                return "Diffie-Hellman";
            case PublicKeyAlgorithmTags.EDDSA:
                return "EdDSA";
            case PublicKeyAlgorithmTags.EXPERIMENTAL_1:
            case PublicKeyAlgorithmTags.EXPERIMENTAL_2:
            case PublicKeyAlgorithmTags.EXPERIMENTAL_3:
            case PublicKeyAlgorithmTags.EXPERIMENTAL_4:
            case PublicKeyAlgorithmTags.EXPERIMENTAL_5:
            case PublicKeyAlgorithmTags.EXPERIMENTAL_6:
            case PublicKeyAlgorithmTags.EXPERIMENTAL_7:
            case PublicKeyAlgorithmTags.EXPERIMENTAL_8:
            case PublicKeyAlgorithmTags.EXPERIMENTAL_9:
            case PublicKeyAlgorithmTags.EXPERIMENTAL_10:
            case PublicKeyAlgorithmTags.EXPERIMENTAL_11:
                return "Experimental - " + keyAlgorithm;
            default:
                throw new UnsupportedOperationException("Unknown key algorithm value encountered: " + keyAlgorithm);
        }
    }
}
