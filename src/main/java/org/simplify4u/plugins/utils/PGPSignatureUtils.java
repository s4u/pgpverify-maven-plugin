/*
 * Copyright 2017 Slawomir Jaranowski
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

package org.simplify4u.plugins.utils;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Optional;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

/**
 * Utilities for PGP Signature class.
 */
public final class PGPSignatureUtils {

    private PGPSignatureUtils() {
        // No need to instantiate utility class.
    }

    /**
     * Check PGP signature for bad algorithms.
     *
     * @param signature PGP signature instance
     *
     * @return Returns null if no bad algorithms used, or algorithm name if used.
     */
    public static String checkWeakHashAlgorithm(PGPSignature signature) {
        switch (signature.getHashAlgorithm()) {
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
                        + signature.getHashAlgorithm());
        }
    }

    /**
     * Load PGPSignature from input stream.
     *
     * @param input the input stream having PGPSignature content
     *
     * @return Returns the (first) read PGP signature.
     *
     * @throws IOException           In case of bad content.
     * @throws PGPSignatureException In case of failure loading signature.
     */
    public static PGPSignature loadSignature(InputStream input) throws IOException, PGPSignatureException {

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
                    while (dataStream.read() > 0) {
                        // we must read whole packet in order to proper input stream shift
                    }
                }
            }
        } catch (PGPException e) {
            throw new PGPSignatureException(e.getMessage(), e);
        }

        throw new PGPSignatureException("PGP signature not found.");
    }

    /**
     * Read the content of a file into the PGP signature instance (for verification).
     *
     * @param signature the PGP signature instance. The instance is expected to be initialized.
     * @param file      the file to read
     *
     * @throws IOException In case of failure to open the file or failure while reading its content.
     */
    public static void readFileContentInto(final PGPSignature signature, final File file) throws IOException {
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
     * @throws PGPSignatureException In case of problem with signature data
     */
    public static PGPKeyId retrieveKeyId(PGPSignature signature) throws PGPSignatureException {

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
            throw new PGPSignatureException(
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
                throw new PGPSignatureException(
                        String.format("Signature IssuerFingerprint 0x%s not contains IssuerKeyID 0x%016X",
                                HexUtils.fingerprintToString(fingerprint), issuerKeyId.get()));
            }
        }

        PGPKeyId pgpKeyId;
        if (issuerFingerprint.isPresent()) {
            pgpKeyId = PGPKeyId.from(issuerFingerprint.get().getFingerprint());
        } else if (issuerKeyId.isPresent()) {
            pgpKeyId = PGPKeyId.from(issuerKeyId.get());
        } else {
            pgpKeyId = PGPKeyId.from(signature.getKeyID());
        }

        return pgpKeyId;
    }
}
