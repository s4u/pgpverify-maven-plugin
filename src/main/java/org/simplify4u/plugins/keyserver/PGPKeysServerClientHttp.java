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
import java.util.function.Function;

import io.vavr.control.Try;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.maven.settings.Proxy;

/**
 * Implementation of a client for requesting keys from PGP key servers over HKP/HTTP.
 */
class PGPKeysServerClientHttp extends PGPKeysServerClient {

    protected PGPKeysServerClientHttp(URI keyserver, int connectTimeout, int readTimeout, int maxAttempts, Proxy proxy)
            throws IOException {

        super(prepareKeyServerURI(keyserver), connectTimeout, readTimeout, maxAttempts, proxy);
    }

    private static URI prepareKeyServerURI(URI keyServer) throws IOException {

        int port;

        if (keyServer.getPort() > 0) {
            port = keyServer.getPort();
        } else if ("hkp".equalsIgnoreCase(keyServer.getScheme())) {
            port = 11371;
        } else {
            port = -1;
        }


        return Try.of(() -> new URI("http", keyServer.getUserInfo(), keyServer.getHost(), port, null, null, null))
                .getOrElseThrow((Function<Throwable, IOException>) IOException::new);
    }

    @Override
    protected HttpClientBuilder createClientBuilder() {
        return setupProxy(HttpClientBuilder.create());
    }
}
