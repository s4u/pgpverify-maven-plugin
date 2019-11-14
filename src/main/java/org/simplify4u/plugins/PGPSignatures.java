package org.simplify4u.plugins;

import org.bouncycastle.openpgp.PGPSignature;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Utilities for PGP Signature class.
 */
final class PGPSignatures {

    /**
     * Read the content of a file into the PGP signature instance (for verification).
     *
     * @param signature the PGP signature instance. The instance is expected to be initialized.
     * @param file      the file to read
     * @throws IOException In case of failure to open the file or failure while reading its content.
     */
    static void readFileContentInto(final PGPSignature signature, final File file) throws IOException {
        try (InputStream inArtifact = new BufferedInputStream(new FileInputStream(file))) {
            int t;
            while ((t = inArtifact.read()) >= 0) {
                signature.update((byte) t);
            }
        }
    }
}
