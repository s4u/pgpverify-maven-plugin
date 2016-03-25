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
 * Implementation of PGPKeysServerClient for HTTPS protocol.
 */
public class PGPKeysServerClientHttps extends PGPKeysServerClient {

    protected PGPKeysServerClientHttps(URI uri) throws URISyntaxException {
        super(uri);
    }

    @Override
    protected URI prepareKeyServerURI(URI keyserver) throws URISyntaxException {
        return new URI("https", keyserver.getUserInfo(), keyserver.getHost(), keyserver.getPort(), null, null, null);
    }

    @Override
    protected InputStream getInputStreamForKey(URL keyURL) throws IOException {
        // standard support by Java - can be extended eg. to support custom CA certs
        return keyURL.openStream();
    }
}
