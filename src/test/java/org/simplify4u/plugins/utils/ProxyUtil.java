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

import org.apache.maven.settings.Proxy;

/**
 * util class to create a maven proxies for testing
 */
public class ProxyUtil {

    /**
     * create a new proxy for tests
     * @param proxyUser the username
     * @param proxyPassword the password
     * @param id the proxy id
     * @return a proxy
     */
    public static Proxy makeMavenProxy(String proxyUser, String proxyPassword, String id, boolean active) {
        Proxy proxy = new Proxy();
        proxy.setHost("localhost");
        proxy.setActive(active);
        proxy.setNonProxyHosts("*");
        proxy.setUsername(proxyUser);
        proxy.setPassword(proxyPassword);
        proxy.setId(id);
        proxy.setProtocol("http");
        return proxy;
    }

    /**
     * create a new proxy for tests
     * @param proxyUser the username
     * @param proxyPassword the password
     * @return a proxy
     */
    public static Proxy makeMavenProxy(String proxyUser, String proxyPassword) {
        return makeMavenProxy(proxyUser, proxyPassword, "MyProxy", true);
    }

    public static Proxy makeMavenProxy(String id) {
        Proxy proxy = new Proxy();
        proxy.setId(id);
        return proxy;
    }
}
