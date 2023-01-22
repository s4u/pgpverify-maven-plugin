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
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.simplify4u.plugins.utils.ProxyUtil.makeMavenProxy;

import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.ProxyAuthenticationStrategy;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Settings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.simplify4u.plugins.pgp.KeyId;

@ExtendWith(MockitoExtension.class)
class PGPKeysServerClientTest {

    @Mock
    Settings settings;

    @Mock
    MavenSession mavenSession;

    @Mock
    HttpClientBuilder clientBuilder;

    public static Proxy[] proxy() {
        return new Proxy[] {
                makeMavenProxy("", ""),
                makeMavenProxy(null, null),
                null};
    }

    @ParameterizedTest
    @MethodSource("proxy")
    void emptyProxyNotConfigureClient(Proxy proxy) throws URISyntaxException, IOException {
        runProxyConfig(proxy);

        verify(clientBuilder).setDefaultRequestConfig(any());
        verifyNoMoreInteractions(clientBuilder);
    }

    @Test
    void mavenProxyShouldConfigureClient() {

        runProxyConfig(makeMavenProxy("user", "userPass"));

        verify(clientBuilder).setProxyAuthenticationStrategy(ProxyAuthenticationStrategy.INSTANCE);

        ArgumentCaptor<CredentialsProvider> cpArgumentCaptor = ArgumentCaptor.forClass(CredentialsProvider.class);
        verify(clientBuilder).setDefaultCredentialsProvider(cpArgumentCaptor.capture());

        assertThat(cpArgumentCaptor.getAllValues()).hasSize(1);

        CredentialsProvider cp = cpArgumentCaptor.getValue();
        Credentials credentials = cp.getCredentials(AuthScope.ANY);

        assertThat(credentials.getUserPrincipal().getName()).isEqualTo("user");
        assertThat(credentials.getPassword()).isEqualTo("userPass");

        verify(clientBuilder).setDefaultRequestConfig(any());
        verifyNoMoreInteractions(clientBuilder);
    }

    private void runProxyConfig(Proxy proxy) {

        when(mavenSession.getSettings()).thenReturn(settings);
        when(settings.getActiveProxy()).thenReturn(proxy);

        KeyServerClientSettings clientSettings = KeyServerClientSettings.builder()
                .mavenSession(mavenSession)
                .build();

        PGPKeysServerClient pgpKeysServerClient = new PGPKeysServerClient(null, clientSettings, () -> clientBuilder);

        pgpKeysServerClient.buildClient(null);
        verify(clientBuilder).build();
    }

    @Test
    void offLineModeShouldThrowIOException() throws URISyntaxException {

        URI uri = new URI("https://localhost/");

        when(mavenSession.isOffline()).thenReturn(true);

        KeyServerClientSettings clientSettings = KeyServerClientSettings.builder()
                .mavenSession(mavenSession)
                .build();

        PGPKeysServerClient pgpKeysServerClient = new PGPKeysServerClient(uri, clientSettings);

        assertThatThrownBy(() -> pgpKeysServerClient.copyKeyToOutputStream(KeyId.from(0x0123456789ABCDEFL), null, null))
                .isExactlyInstanceOf(IOException.class)
                .hasMessage("Not possible to download key: https://localhost/pks/lookup?op=get&options=mr&search=0x0123456789ABCDEF in offline mode.");
    }

    @Test
    void unsupportedProtocolShouldThrowIOException() throws IOException {
        assertThatThrownBy(() -> PGPKeysServerClient.getClient("abc://loclahost", null))
                .isExactlyInstanceOf(IOException.class)
                .hasMessage("Unsupported protocol: abc");
    }

    @Test
    void serverResponse404() throws URISyntaxException, IOException {

        when(mavenSession.getSettings()).thenReturn(settings);

        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        CloseableHttpResponse httpResponse = mock(CloseableHttpResponse.class);
        StatusLine statusLine = mock(StatusLine.class);

        when(clientBuilder.build()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(HttpStatus.SC_NOT_FOUND);

        KeyServerClientSettings clientSettings = KeyServerClientSettings.builder()
                .mavenSession(mavenSession)
                .build();

        PGPKeysServerClient pgpKeysServerClient = new PGPKeysServerClient(new URI("https://example.com"),
                clientSettings, () -> clientBuilder);

        assertThatCode(() -> pgpKeysServerClient.copyKeyToOutputStream(KeyId.from(0x1L), null, null))
                .isExactlyInstanceOf(PGPKeyNotFound.class)
                .hasMessage("PGP server returned an error: HTTP/1.1 404 Not Found for: "
                        + "https://example.com/pks/lookup?op=get&options=mr&search=0x0000000000000001");
    }

    @Test
    void serverIOException() throws URISyntaxException, IOException {

        when(mavenSession.getSettings()).thenReturn(settings);

        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);

        when(clientBuilder.build()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenThrow(new IOException("Test IOException"));

        KeyServerClientSettings clientSettings = KeyServerClientSettings.builder()
                .mavenSession(mavenSession)
                .build();

        PGPKeysServerClient pgpKeysServerClient = new PGPKeysServerClient(new URI("https://example.com"),
                clientSettings, () -> clientBuilder);

        AtomicInteger onRetryCounter = new AtomicInteger();

        PGPKeysServerClient.OnRetryConsumer onRetryConsumer = (address, numberOfRetryAttempts, waitInterval, lastThrowable)
                -> {
            onRetryCounter.getAndIncrement();
            assertThat(lastThrowable).isExactlyInstanceOf(IOException.class);
        };

        assertThatCode(() -> pgpKeysServerClient.copyKeyToOutputStream(KeyId.from(0x1L), null, onRetryConsumer))
                .isExactlyInstanceOf(IOException.class)
                .hasMessage("Test IOException for: "
                        + "https://example.com/pks/lookup?op=get&options=mr&search=0x0000000000000001");

        assertThat(onRetryCounter).hasValue(5);
    }
}
