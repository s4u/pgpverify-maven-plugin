package org.simplify4u.plugins.keyserver;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.maven.settings.Proxy;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import static org.simplify4u.plugins.utils.ProxyUtil.makeMavenProxy;

public class PGPKeysServerClientTest {

    @DataProvider(name = "proxy")
    public static Object[][] proxy() {
        return new Object[][]{
                { makeMavenProxy("user", "password") },
                { makeMavenProxy("", "") },
                { makeMavenProxy(null, null) },
                { null }};
    }

    @Test(dataProvider = "proxy")
    public void testIfClientWithProxyProperties(Proxy proxy) throws URISyntaxException, IOException {
        URI uri = new URI("https://localhost/");

        runProxyConfig(uri, proxy);
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