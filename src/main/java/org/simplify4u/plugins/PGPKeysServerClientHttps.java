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
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;

/**
 * Implementation of a client for requesting keys from PGP key servers over HKPS/HTTPS.
 */
public class PGPKeysServerClientHttps extends PGPKeysServerClient {
    private final SSLConnectionSocketFactory sslSocketFactory;

    protected PGPKeysServerClientHttps(final URI uri, final int connectTimeout,
                                       final int readTimeout)
    throws URISyntaxException, CertificateException, IOException, KeyStoreException,
           NoSuchAlgorithmException, KeyManagementException {
        super(uri, connectTimeout, readTimeout);

        if (uri.getHost().toLowerCase().endsWith("sks-keyservers.net")) {
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

            this.sslSocketFactory
                = new SSLConnectionSocketFactory(
                    context, SSLConnectionSocketFactory.getDefaultHostnameVerifier());
        } else {
            this.sslSocketFactory = SSLConnectionSocketFactory.getSystemSocketFactory();
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
    protected HttpClientBuilder createClientBuilder() {
        return HttpClients.custom().setSSLSocketFactory(this.sslSocketFactory);
    }
}
