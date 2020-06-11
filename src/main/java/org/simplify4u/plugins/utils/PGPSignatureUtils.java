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

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
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
     * @return Returns the (first) read PGP signature.
     * @throws IOException In case of bad content.
     */
    public static PGPSignature loadSignature(InputStream input) throws IOException, PGPSignatureException {
        InputStream sigInputStream = PGPUtil.getDecoderStream(input);
        PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(sigInputStream, new BcKeyFingerprintCalculator());
        Object object = pgpObjectFactory.nextObject();
        if (!(object instanceof PGPSignatureList)) {
            throw new PGPSignatureException("File content is not a PGP signature.");
        }
        PGPSignatureList siglist = (PGPSignatureList) object;
        if (siglist.isEmpty()) {
            throw new PGPSignatureException("PGP signature list is empty.");
        }
        return siglist.get(0);
    }

    /**
     * Read the content of a file into the PGP signature instance (for verification).
     *
     * @param signature
     *         the PGP signature instance. The instance is expected to be initialized.
     * @param file
     *         the file to read
     *
     * @throws IOException
     *         In case of failure to open the file or failure while reading its content.
     */
    public static void readFileContentInto(final PGPSignature signature, final File file) throws IOException {
        try (InputStream inArtifact = new BufferedInputStream(new FileInputStream(file))) {
            int t;
            while ((t = inArtifact.read()) >= 0) {
                signature.update((byte) t);
            }
        }
    }
}
