/*
 * Copyright 2016 Slawomir Jaranowski
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

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * Common support for communication with key servers.
 */
abstract class PGPKeysServerClient {

    private final URI keyserver;

    protected PGPKeysServerClient(URI keyserver) throws URISyntaxException {
        this.keyserver = prepareKeyServerURI(keyserver);
    }

    /**
     * Create PGPKeysServerClient instance for specific protocol.
     * @param keyserver - key server address
     * @return PGPKeysServerClient
     * @throws URISyntaxException if something wrong with key server address
     */
    static PGPKeysServerClient getInstance(String keyserver)
            throws URISyntaxException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
        URI uri = new URI(keyserver);
        switch (uri.getScheme().toLowerCase()) {
            case "hkp":
            case "http":
                return new PGPKeysServerClientHttp(uri);
            case "hkps":
            case "https":
                return new PGPKeysServerClientHttps(uri);
            default:
                throw new URISyntaxException(keyserver, "Unsupported protocol");
        }
    }

    private String getQueryStringForGetKey(long keyID) {
        return String.format("op=get&options=mr&search=0x%016X", keyID);
    }

    /**
     * Create URI for key download.
     *
     * @param keyID key ID
     * @return URI with given key
     */
    URI getUriForGetKey(long keyID) {
        try {
            return new URI(keyserver.getScheme(), keyserver.getUserInfo(),
                    keyserver.getHost(), keyserver.getPort(),
                    "/pks/lookup", getQueryStringForGetKey(keyID), null);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(String.format("URI exception for keyId 0x%016X", keyID), e);
        }
    }

    private String getQueryStringForShowKey(long keyID) {
        return String.format("op=vindex&fingerprint=on&search=0x%016X", keyID);
    }

    /**
     * Create URI for key lookup.
     *
     * @param keyID key ID
     * @return URI with given key
     */
    URI getUriForShowKey(long keyID) {
        try {
            return new URI(keyserver.getScheme(), keyserver.getUserInfo(),
                    keyserver.getHost(), keyserver.getPort(),
                    "/pks/lookup", getQueryStringForShowKey(keyID), null);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(String.format("URI exception for keyId 0x%016X", keyID), e);
        }
    }

    /**
     * Open connection to key server and return input stream for given key id.
     *
     * @param keyID  key id
     * @return InputStream for key
     * @throws IOException if communication fails
     */
    InputStream getInputStreamForKey(long keyID) throws IOException {
        return getInputStreamForKey(getUriForGetKey(keyID).toURL());
    }

    // abstract methods to implemented in child class.

    /**
     * Return URI to using for communication with key server.
     *
     * This method must change protocol from pgp key server specific to supported by java.
     * Eg. hkp -> http
     *
     * @param keyserver key server address
     * @return URI for given key server
     * @throws URISyntaxException if key server address is wrong
     */
    protected abstract URI prepareKeyServerURI(URI keyserver) throws URISyntaxException;

    /**
     * Open connection to key server and return input stream for given key url.
     *
     * @param keyURL url for key file
     * @return InputStream for key
     * @throws IOException if communication fails
     */
    protected abstract InputStream getInputStreamForKey(URL keyURL) throws IOException;
}

