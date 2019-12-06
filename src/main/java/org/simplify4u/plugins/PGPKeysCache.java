/*
 * Copyright 2017 Slawomir Jaranowski
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

package org.simplify4u.plugins;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Optional;

import org.apache.maven.plugin.logging.Log;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

/**
 * @author Slawomir Jaranowski.
 */
public class PGPKeysCache {

    private final Log log;
    private final File cachePath;
    private final PGPKeysServerClient keysServerClient;

    private static final Object LOCK = new Object();

    public PGPKeysCache(Log log, File cachePath, String keyServer)
            throws URISyntaxException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException,
            KeyManagementException {

        this.log = log;
        this.cachePath = cachePath;
        keysServerClient = PGPKeysServerClient.getClient(keyServer);

        synchronized (LOCK) {
            if (this.cachePath.exists()) {
                if (!this.cachePath.isDirectory()) {
                    throw new IOException("PGP keys cache path exist but is not a directory: " + this.cachePath);
                }
            } else {
                if (this.cachePath.mkdirs()) {
                    this.log.info("Create cache directory for PGP keys: " + this.cachePath);
                } else {
                    throw new IOException("Cache directory create error");
                }
            }
        }
    }

    String getUrlForShowKey(long keyID) {
        return keysServerClient.getUriForShowKey(keyID).toString();
    }

    PGPPublicKey getKey(long keyID) throws IOException, PGPException {

        PGPPublicKey key = null;

        String path = String.format("%02X/%02X/%016X.asc", (byte) (keyID >> 56), (byte) (keyID >> 48 & 0xff), keyID);
        File keyFile = new File(cachePath, path);

        synchronized (LOCK) {

            if (!keyFile.exists()) {
                receiveKey(keyFile, keyID);
            }

            try (InputStream keyIn = PGPUtil.getDecoderStream(new FileInputStream(keyFile))) {
                PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(keyIn, new BcKeyFingerprintCalculator());
                key = pgpRing.getPublicKey(keyID);
                if (key == null) {
                    throw new PGPException(String.format("Can't find public key in download file: %s" , keyFile));
                }
            } finally {
                if (key == null) {
                    deleteFile(keyFile);
                }
            }
        }
        return key;
    }

    private void receiveKey(File keyFile, long keyId) throws IOException {
        File dir = keyFile.getParentFile();

        if (dir == null) {
            throw new IOException("No parent dir for: " + keyFile);
        }

        if (dir.exists() && !dir.isDirectory()) {
            throw new IOException("Path exist but it isn't directory: " + dir);
        }

        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("Can't create directory: " + dir);
        }

        File partFile = File.createTempFile(String.valueOf(keyId), "pgp-public-key");

        try {
            try (BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(partFile))) {
                keysServerClient.copyKeyToOutputStream(keyId, outputStream, new PGPServerRetryHandler(this.log));
            }
            Files.move(partFile.toPath(), keyFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            // if error try remove file
            deleteFile(keyFile);
            deleteFile(partFile);
            throw e;
        }

        log.info(String.format("Receive key: %s%n\tto %s", keysServerClient.getUriForGetKey(keyId), keyFile));
    }

    private void deleteFile(File file) {

        Optional.ofNullable(file)
                .map(File::toPath)
                .ifPresent(filePath -> {
                            try {
                                Files.deleteIfExists(filePath);
                            } catch (IOException e) {
                                log.warn("Can't delete: " + filePath);
                            }
                        }
                );
    }
}
