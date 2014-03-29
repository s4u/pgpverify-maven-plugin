/*
 * Copyright 2014 Slawomir Jaranowski
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

package com.github.s4u.plugins;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import com.google.common.io.Resources;
import org.apache.maven.plugin.logging.Log;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;

/**
 * @author Slawomir Jaranowski.
 */
public class PGPKeysCache {

    private final Log log;
    private final File cachePath;
    private final String keyServer;

    public PGPKeysCache(Log log, File cachePath, String keyServer) throws URISyntaxException {

        this.log = log;
        this.cachePath = cachePath;

        URI uri = new URI(keyServer);
        String scheme = uri.getScheme();
        int port = uri.getPort();
        if ("hkp".equalsIgnoreCase(uri.getScheme())) {
            scheme = "http";
            port = 11371;
        }

        uri = new URI(scheme, uri.getUserInfo(), uri.getHost(), port,
                "/pks/lookup", "op=get&options=mr&search=", null);

        this.keyServer = uri.toString() + "0x%016X";
        log.debug("KeyServerPath=" + this.keyServer);
    }

    public PGPPublicKey getKey(long keyID) throws IOException, PGPException {

        File keyFile = null;
        PGPPublicKey key = null;

        try {
            String path = String.format("%02X/%02X/%016X.asc",
                    (byte) (keyID >> 56), (byte) (keyID >> 48 & 0xff), keyID);

            keyFile = new File(cachePath, path);
            if (!keyFile.exists()) {
                receiveKey(keyFile, keyID);
            }

            InputStream keyIn = PGPUtil.getDecoderStream(new FileInputStream(keyFile));
            PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(keyIn);
            key = pgpRing.getPublicKey(keyID);
        } finally {
            if (key == null && keyFile != null && keyFile.exists()) {
                if (!keyFile.delete()) {
                    log.warn("Can't delete: " + keyFile);
                }
            }
        }
        return key;
    }

    private void receiveKey(File keyFile, long keyID) throws IOException {

        File dir = keyFile.getParentFile();
        if (dir == null) {
            throw new IOException("No parent dir for: " + keyFile);
        }

        if (dir.exists() && !dir.isDirectory()) {
            throw new IOException("Path exist but it isn't directory: " + dir);
        }

        if (!dir.exists()) {
            if (dir.mkdirs()) {
                if (!dir.exists()) {
                    throw new IOException("Can't create directory: " + dir);
                }
            }
        }

        URL keyUrl = URI.create(String.format(keyServer, keyID)).toURL();
        try (BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(keyFile))) {
            Resources.copy(keyUrl, outputStream);
        } catch (IOException e) {
            // if error try remove file
            if (keyFile.exists()) {
                if (!keyFile.delete()) {
                    throw new IOException("Can't delete: " + keyFile, e);
                }
            }
            throw e;
        }

        log.info(String.format("Receive key: %X to %s", keyID, keyFile));
    }
}
