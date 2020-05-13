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

import org.bouncycastle.openpgp.PGPSignature;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Utilities for PGP Signature class.
 */
public final class PGPSignatureUtils {

    private PGPSignatureUtils() {
        // No need to instantiate utility class.
    }

    /**
     * Read the content of a file into the PGP signature instance (for verification).
     *
     * @param signature the PGP signature instance. The instance is expected to be initialized.
     * @param file      the file to read
     * @throws IOException In case of failure to open the file or failure while reading its content.
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
