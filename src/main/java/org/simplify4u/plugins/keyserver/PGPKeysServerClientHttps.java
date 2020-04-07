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

import java.io.IOException;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Locale;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import io.vavr.control.Try;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.maven.settings.Proxy;

/**
 * Implementation of a client for requesting keys from PGP key servers over HKPS/HTTPS.
 */
class PGPKeysServerClientHttps extends PGPKeysServerClient {
    private final SSLConnectionSocketFactory sslSocketFactory;

    protected PGPKeysServerClientHttps(URI uri, int connectTimeout, int readTimeout, int maxAttempts, Proxy proxy)
            throws IOException {

        super(prepareKeyServerURI(uri), connectTimeout, readTimeout, maxAttempts, proxy);

        try {
            if (uri.getHost().toLowerCase(Locale.ROOT).endsWith("sks-keyservers.net")) {
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
        } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | KeyManagementException e) {
            throw new IOException(e);
        }
    }

    private static URI prepareKeyServerURI(URI keyserver) {

        return Try.of(() ->
                new URI("https", keyserver.getUserInfo(), keyserver.getHost(), keyserver.getPort(),
                        null, null, null)).get();
    }

    @Override
    protected HttpClientBuilder createClientBuilder() {
        return setupProxy(HttpClients.custom().setSSLSocketFactory(this.sslSocketFactory));
    }
}
