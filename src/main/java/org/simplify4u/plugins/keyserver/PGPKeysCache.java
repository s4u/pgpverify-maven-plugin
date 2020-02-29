/*
 * Copyright 2020 Slawomir Jaranowski
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

package org.simplify4u.plugins.keyserver;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.Optional;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.simplify4u.plugins.utils.PublicKeyUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Slawomir Jaranowski.
 */
public class PGPKeysCache {

    private static final Logger LOGGER = LoggerFactory.getLogger(PGPKeysCache.class);
    private static final String NL = System.lineSeparator();

    private final File cachePath;
    private final PGPKeysServerClient keysServerClient;

    private static final Object LOCK = new Object();

    public PGPKeysCache(File cachePath, PGPKeysServerClient keysServerClient) throws IOException {

        this.cachePath = cachePath;
        this.keysServerClient = keysServerClient;

        synchronized (LOCK) {
            if (this.cachePath.exists()) {
                if (!this.cachePath.isDirectory()) {
                    throw new IOException("PGP keys cache path exist but is not a directory: " + this.cachePath);
                }
            } else {
                if (this.cachePath.mkdirs()) {
                    LOGGER.info("Create cache directory for PGP keys: {}", this.cachePath);
                } else {
                    throw new IOException("Cache directory create error");
                }
            }
        }
    }

    public static PGPKeysServerClient prepareClient(String keyserver) throws IOException {
        return PGPKeysServerClient.getClient(keyserver);
    }

    public String getUrlForShowKey(long keyID) {
        return keysServerClient.getUriForShowKey(keyID).toString();
    }

    public PGPPublicKeyRing getKeyRing(long keyID) throws IOException, PGPException {

        Optional<PGPPublicKeyRing> keyRing = Optional.empty();

        String path = String.format("%02X/%02X/%016X.asc", (byte) (keyID >> 56), (byte) (keyID >> 48 & 0xff), keyID);
        File keyFile = new File(cachePath, path);

        synchronized (LOCK) {

            if (!keyFile.exists()) {
                receiveKey(keyFile, keyID);
            }

            try (InputStream keyFileStream = new FileInputStream(keyFile)) {
                keyRing = PublicKeyUtils.loadPublicKeyRing(keyFileStream, keyID);
                return keyRing.orElseThrow(() ->
                        new PGPException(String.format("Can't find public key 0x%016X in download file: %s", keyID, keyFile)));
            } finally {
                if (!keyRing.isPresent()) {
                    deleteFile(keyFile);
                }
            }
        }
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
                keysServerClient.copyKeyToOutputStream(keyId, outputStream, this::onRetry);
            }
            Files.move(partFile.toPath(), keyFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            // if error try remove file
            deleteFile(keyFile);
            deleteFile(partFile);
            throw e;
        }

        LOGGER.info("Receive key: {}{}\tto {}", keysServerClient.getUriForGetKey(keyId), NL, keyFile);
    }

    private void onRetry(InetAddress address, int numberOfRetryAttempts, Duration waitInterval, Throwable lastThrowable) {
        LOGGER.warn("[Retry #{} waiting: {}] Last address {} with problem: {}",
                numberOfRetryAttempts, waitInterval, address, lastThrowable);
    }

    private void deleteFile(File file) {

        Optional.ofNullable(file)
                .map(File::toPath)
                .ifPresent(filePath -> {
                            try {
                                Files.deleteIfExists(filePath);
                            } catch (IOException e) {
                                LOGGER.warn("Can't delete: {}", filePath);
                            }
                        }
                );
    }
}
