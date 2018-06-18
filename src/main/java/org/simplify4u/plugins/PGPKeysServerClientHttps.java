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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * Implementation of PGPKeysServerClient for HTTPS protocol.
 */
public class PGPKeysServerClientHttps extends PGPKeysServerClient {

    private final SSLSocketFactory sslSocketFactory;

    protected PGPKeysServerClientHttps(final URI uri, final int connectTimeout,
                                       final int readTimeout)
    throws URISyntaxException, CertificateException, IOException, KeyStoreException,
           NoSuchAlgorithmException, KeyManagementException {
        super(uri, connectTimeout, readTimeout);

        if ("hkps.pool.sks-keyservers.net".equalsIgnoreCase(uri.getHost())) {
            final CertificateFactory cf = CertificateFactory.getInstance("X.509");
            final Certificate ca = cf.generateCertificate(
                getClass().getClassLoader().getResourceAsStream("sks-keyservers.netCA.pem"));

            final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

            keyStore.load(null, null);
            keyStore.setCertificateEntry("ca", ca);

            final TrustManagerFactory tmf
                = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            final SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, tmf.getTrustManagers(), null);

            this.sslSocketFactory = context.getSocketFactory();
        } else {
            this.sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        }
    }

    @Override
    protected URI prepareKeyServerURI(URI keyserver) throws URISyntaxException {
        return new URI(
            "https",
            keyserver.getUserInfo(),
            keyserver.getHost(),
            keyserver.getPort(),
            null,
            null,
            null);
    }

    @Override
    protected URLConnection getConnectionForKeyUrl(URL keyUrl) throws IOException {
        // standard support by Java - can be extended eg. to support custom CA certs
        final HttpsURLConnection connection = (HttpsURLConnection) keyUrl.openConnection();

        connection.setSSLSocketFactory(sslSocketFactory);

        this.applyTimeouts(connection);

        return connection;
    }
}
