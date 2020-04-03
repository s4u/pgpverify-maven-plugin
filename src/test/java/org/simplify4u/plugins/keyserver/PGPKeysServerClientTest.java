package org.simplify4u.plugins.keyserver;

import static org.simplify4u.plugins.utils.ProxyUtil.makeMavenProxy;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.maven.settings.Proxy;
import org.testng.Assert;
import org.testng.annotations.Test;

public class PGPKeysServerClientTest {

    @Test
    public void testIfClientWithProxySetsProperties() throws URISyntaxException, IOException {
        URI uri = new URI("https://localhost/");
        Proxy proxy = makeMavenProxy("user", "password");

        runProxyConfig(uri, proxy);
    }

    @Test
    public void testIfClientWithOutProxyIsIgnored() throws URISyntaxException, IOException {
        URI uri = new URI("https://localhost/");
        Proxy proxy = makeMavenProxy("", "");

        runProxyConfig(uri, proxy);
    }
    @Test
    public void testIfClientWithOutProxyIsIgnored2() throws URISyntaxException, IOException {
        URI uri = new URI("https://localhost/");
        Proxy proxy = makeMavenProxy(null, null);

        runProxyConfig(uri, proxy);
    }

    @Test
    public void testIfNoProxyWorks() throws URISyntaxException, IOException {
        URI uri = new URI("https://localhost/");

        runProxyConfig(uri, null);
    }

    private void runProxyConfig(URI uri, Proxy proxy) throws IOException {
        PGPKeysServerClient pgpKeysServerClient = new PGPKeysServerClient(uri, 10_000, 10_000, 10_000, proxy) {
            @Override
            protected HttpClientBuilder createClientBuilder() {
                return null;
            }
        };
        HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();

        pgpKeysServerClient.setupProxy(httpClientBuilder);
        try (CloseableHttpClient closeableHttpClient = httpClientBuilder.build()) {
            // client can be created - cannot look inside if it actually worked because all setters are final.
            Assert.assertNotNull(closeableHttpClient);
        }
    }
}