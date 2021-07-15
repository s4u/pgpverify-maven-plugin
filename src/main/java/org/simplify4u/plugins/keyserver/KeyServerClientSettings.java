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

import java.util.Collections;
import java.util.Optional;

import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.settings.Proxy;

/**
 * Provide settings for key server client connection.
 */
@Builder
@Getter
public class KeyServerClientSettings {

    private static final int DEFAULT_CONNECT_TIMEOUT = 1000;
    private static final int DEFAULT_READ_TIMEOUT = 5000;
    public static final int DEFAULT_MAX_RETRIES = 5;

    @NonNull
    MavenSession mavenSession;

    String proxyName;

    @Builder.Default
    int connectTimeout = DEFAULT_CONNECT_TIMEOUT;

    @Builder.Default
    int readTimeout = DEFAULT_READ_TIMEOUT;

    @Builder.Default
    int maxRetries = DEFAULT_MAX_RETRIES;

    public Optional<Proxy> getProxy() {

        if (proxyName == null) {
            return Optional.ofNullable(mavenSession.getSettings().getActiveProxy());
        }

        return Optional.ofNullable(mavenSession.getSettings().getProxies()).orElse(Collections.emptyList())
                .stream()
                .filter(proxy -> proxyName.equalsIgnoreCase(proxy.getId()))
                .findFirst();
    }

    public boolean isOffline() {
        return mavenSession.isOffline();
    }
}
