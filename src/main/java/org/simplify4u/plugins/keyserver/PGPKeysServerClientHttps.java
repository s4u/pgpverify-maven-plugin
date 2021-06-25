/*
 * Copyright 2021 Slawomir Jaranowski
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

import java.net.URI;

import io.vavr.control.Try;

/**
 * Implementation of a client for requesting keys from PGP key servers over HKPS/HTTPS.
 */
class PGPKeysServerClientHttps extends PGPKeysServerClient {

    protected PGPKeysServerClientHttps(URI uri, KeyServerClientSettings keyServerClientSettings) {
        super(prepareKeyServerURI(uri), keyServerClientSettings);
    }

    private static URI prepareKeyServerURI(URI keyserver) {

        return Try.of(() ->
                new URI("https", keyserver.getUserInfo(), keyserver.getHost(), keyserver.getPort(),
                        null, null, null)).get();
    }
}
