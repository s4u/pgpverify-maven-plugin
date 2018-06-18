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

import com.google.common.io.ByteStreams;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import org.simplify4u.plugins.failurestrategies.NoRetryStrategy;
import org.simplify4u.plugins.failurestrategies.RequestFailureStrategy;

/**
 * Common support for communication with key servers.
 */
abstract class PGPKeysServerClient {
    private static final int DEFAULT_CONNECT_TIMEOUT = 5000;
    private static final int DEFAULT_READ_TIMEOUT = 20000;

    private final URI keyserver;
    private final int connectTimeout;
    private final int readTimeout;

    protected PGPKeysServerClient(final URI keyserver, final int connectTimeout,
                                  final int readTimeout) throws URISyntaxException {
        this.keyserver = prepareKeyServerURI(keyserver);
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
    }

    /**
     * Create a PGP key server for a given URL.
     *
     * @param keyServer
     *   The key server address / URL.
     *
     * @return
     *   The right PGP client for the given address.
     *
     * @throws URISyntaxException
     *   If the key server address is invalid or improperly-formatted.
     */
    static PGPKeysServerClient getClient(final String keyServer)
    throws URISyntaxException, CertificateException, NoSuchAlgorithmException, KeyStoreException,
           KeyManagementException, IOException {
        return getClient(keyServer, DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT);
    }

    /**
     * Create a PGP key server for a given URL.
     *
     * @param keyServer
     *   The key server address / URL.
     * @param connectTimeout
     *   The timeout (in milliseconds) that the client should wait to establish a connection to
     *   the PGP server.
     * @param readTimeout
     *   The timeout (in milliseconds) that the client should wait for data from the PGP server.
     *
     * @return
     *   The right PGP client for the given address.
     *
     * @throws URISyntaxException
     *   If the key server address is invalid or improperly-formatted.
     */
    static PGPKeysServerClient getClient(final String keyServer, final int connectTimeout,
                                         final int readTimeout)
    throws URISyntaxException, CertificateException, NoSuchAlgorithmException, KeyStoreException,
           KeyManagementException, IOException {
        final URI uri = new URI(keyServer);
        final String protocol = uri.getScheme().toLowerCase();

        switch (protocol) {
            case "hkp":
            case "http":
                return new PGPKeysServerClientHttp(uri, connectTimeout, readTimeout);

            case "hkps":
            case "https":
                return new PGPKeysServerClientHttps(uri, connectTimeout, readTimeout);

            default:
                throw new URISyntaxException(keyServer, "Unsupported protocol: " + protocol);
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
            throw new IllegalArgumentException(
                String.format("URI exception for keyId 0x%016X", keyID), e);
        }
    }

    /**
     * Requests the PGP key with the specified key ID from the server and copies it to the specified
     * output stream.
     *
     * <p>If the request fails, it will not be retried, and an {@link IOException} will be thrown.
     *
     * @param keyId
     *   The ID of the key to request from the server.
     * @param outputStream
     *   The output stream to which the key will be written.
     *
     * @throws IOException
     *   If the request fails, or the key cannot be written to the output stream.
     */
    void copyKeyToOutputStream(long keyId, OutputStream outputStream) throws IOException {
        this.copyKeyToOutputStream(keyId, outputStream, new NoRetryStrategy());
    }

    /**
     * Requests the PGP key with the specified key ID from the server and copies it to the specified
     * output stream.
     *
     * <p>If the request fails, based on the type of failure the request may be silently retried
     * unless instructed otherwise by the provided failure strategy. If a failure occurs and the
     * strategy indicates that the request should not be retried, the exception will be re-thrown.
     *
     * @param keyId
     *   The ID of the key to request from the server.
     * @param outputStream
     *   The output stream to which the key will be written.
     * @param failureStrategy
     *   The strategy that controls whether or not to retry failing PGP requests. The strategy is
     *   also notified when a retry is attempted.
     *
     * @throws IOException
     *   If the request fails, or the key cannot be written to the output stream.
     */
    void copyKeyToOutputStream(long keyId, OutputStream outputStream,
                               final RequestFailureStrategy failureStrategy) throws IOException {
        final URL keyUrl = getUriForGetKey(keyId).toURL();
        boolean shouldRetry = false;

        do {
            final URLConnection connection = this.getConnectionForKeyUrl(keyUrl);

            try (final InputStream inputStream = connection.getInputStream()) {
                ByteStreams.copy(inputStream, outputStream);
            } catch (IOException ex) {
                if (failureStrategy.canRetry(keyUrl, connection, ex)) {
                    shouldRetry = true;

                    failureStrategy.onRetry(keyUrl, ex);
                } else {
                    throw ex;
                }
            }
        } while (shouldRetry);
    }

    /**
     * Sets connect and read timeouts on the given connection.
     *
     * @param connection
     *   The connection on which timeouts are to be applied.
     */
    protected void applyTimeouts(final URLConnection connection) {
        connection.setConnectTimeout(this.connectTimeout);
        connection.setReadTimeout(this.readTimeout);
    }

    // abstract methods to implemented in child class.

    /**
     * Return URI to using for communication with key server.
     *
     * This method must change protocol from pgp key server specific to supported by java.
     * Eg. hkp to http
     *
     * @param keyserver key server address
     * @return URI for given key server
     * @throws URISyntaxException if key server address is wrong
     */
    protected abstract URI prepareKeyServerURI(URI keyserver) throws URISyntaxException;

    /**
     * Create a connection for the given key server URL, and then returns it.
     *
     * @param keyUrl
     *   url for key file
     *
     * @return
     *   connection for the key
     *
     * @throws IOException
     *   if the connection cannot be created or opened.
     */
    protected abstract URLConnection getConnectionForKeyUrl(URL keyUrl) throws IOException;
}

