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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;
import static org.simplify4u.plugins.utils.ProxyUtil.makeMavenProxy;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Settings;
import org.mockito.Mock;
import org.mockito.testng.MockitoTestNGListener;
import org.simplify4u.plugins.pgp.KeyId;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

@Listeners(MockitoTestNGListener.class)
public class PGPKeysServerClientTest {

    @Mock
    Settings settings;

    @Mock
    MavenSession mavenSession;

    @DataProvider(name = "proxy")
    public static Object[][] proxy() {
        return new Object[][]{
                {makeMavenProxy("user", "password")},
                {makeMavenProxy("", "")},
                {makeMavenProxy(null, null)},
                {null}};
    }

    @Test(dataProvider = "proxy")
    public void testIfClientWithProxyProperties(Proxy proxy) throws URISyntaxException, IOException {
        URI uri = new URI("https://localhost/");

        runProxyConfig(uri, proxy);
    }

    private void runProxyConfig(URI uri, Proxy proxy) throws IOException {

        when(mavenSession.getSettings()).thenReturn(settings);
        when(settings.getActiveProxy()).thenReturn(proxy);
        KeyServerClientSettings clientSettings = KeyServerClientSettings.builder()
                .mavenSession(mavenSession)
                .build();

        PGPKeysServerClient pgpKeysServerClient = new PGPKeysServerClient(uri, clientSettings) {
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


    @Test
    public void offLineModeShouldThrowIOException() throws URISyntaxException {

        URI uri = new URI("https://localhost/");

        when(mavenSession.isOffline()).thenReturn(true);

        KeyServerClientSettings clientSettings = KeyServerClientSettings.builder()
                .mavenSession(mavenSession)
                .build();

        PGPKeysServerClient pgpKeysServerClient = new PGPKeysServerClient(uri, clientSettings) {
            @Override
            protected HttpClientBuilder createClientBuilder() {
                return null;
            }
        };

        assertThatThrownBy(() -> pgpKeysServerClient.copyKeyToOutputStream(KeyId.from(0x0123456789ABCDEFL), null, null))
                .isExactlyInstanceOf(IOException.class)
                .hasMessage("Not possible to download key: https://localhost/pks/lookup?op=get&options=mr&search=0x0123456789ABCDEF in offline mode.");
    }

    @Test
    public void unsupportedProtocolShouldThrowIOException() throws IOException {
        assertThatThrownBy(() -> PGPKeysServerClient.getClient("abc://loclahost", null))
                .isExactlyInstanceOf(IOException.class)
                .hasMessage("Unsupported protocol: abc");
    }
}
