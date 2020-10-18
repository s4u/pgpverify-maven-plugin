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
package org.simplify4u.plugins.utils;

import java.util.Collections;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Settings;

@Named
@Singleton
public class MavenProxy {

    private final Settings settings;

    @Inject
    public MavenProxy(Settings settings) {
        this.settings = settings;
    }

    public Proxy getProxyByName(String proxyName) {

        if (proxyName == null) {
            return settings.getActiveProxy();
        }

        return Optional.ofNullable(settings.getProxies()).orElse(Collections.emptyList())
                .stream()
                .filter(proxy -> proxyName.equalsIgnoreCase(proxy.getId()))
                .findFirst()
                .orElse(null);
    }
}
