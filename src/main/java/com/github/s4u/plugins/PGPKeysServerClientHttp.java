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

/**
 * Implementation of PGPKeysServerClient for HTTP protocol.
 */
class PGPKeysServerClientHttp extends PGPKeysServerClient {

    protected PGPKeysServerClientHttp(URI keyserver) throws URISyntaxException {
        super(keyserver);
    }

    @Override
    protected URI prepareKeyServerURI(URI keyserver) throws URISyntaxException {

        int port = -1;
        if (keyserver.getPort() > 0) {
            port = keyserver.getPort();
        } else if ("hkp".equalsIgnoreCase(keyserver.getScheme())) {
            port = 11371;
        }
        return new URI("http", keyserver.getUserInfo(), keyserver.getHost(), port, null, null, null);
    }

    @Override
    protected InputStream getInputStreamForKey(URL keyURL) throws IOException {
        return keyURL.openStream();
    }
}
