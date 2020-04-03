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
}
