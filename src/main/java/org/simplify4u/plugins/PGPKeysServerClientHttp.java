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

/**
 * Implementation of PGPKeysServerClient for HTTP protocol.
 */
class PGPKeysServerClientHttp extends PGPKeysServerClient {
    protected PGPKeysServerClientHttp(final URI keyserver, final int connectTimeout,
                                      final int readTimeout)
    throws URISyntaxException {
        super(keyserver, connectTimeout, readTimeout);
    }

    @Override
    protected URI prepareKeyServerURI(URI keyServer) throws URISyntaxException {

        int port = -1;

        if (keyServer.getPort() > 0) {
            port = keyServer.getPort();
        } else if ("hkp".equalsIgnoreCase(keyServer.getScheme())) {
            port = 11371;
        }

        return new URI(
            "http", keyServer.getUserInfo(), keyServer.getHost(), port, null, null, null);
    }

    @Override
    protected URLConnection getConnectionForKeyUrl(URL keyUrl) throws IOException {
        final URLConnection connection = keyUrl.openConnection();

        this.applyTimeouts(connection);

        return connection;
    }
}
