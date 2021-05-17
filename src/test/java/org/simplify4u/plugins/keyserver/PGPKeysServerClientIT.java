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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.settings.Settings;
import org.mockserver.client.MockServerClient;
import org.mockserver.configuration.ConfigurationProperties;
import org.mockserver.integration.ClientAndServer;
import org.simplify4u.plugins.pgp.KeyId;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class PGPKeysServerClientIT {
    private static final KeyId TEST_KEYID = KeyId.from(0xF8484389379ACEACL);

    private static final int SHORT_TEST_TIMEOUT = 500;

    private ClientAndServer mockServer;

    private MavenSession mavenSession;

    @DataProvider(name = "goodServerUrls")
    Object[][] goodServerUrls() {
        return new Object[][]{
                {"hkp://pool.sks-keyservers.net"},
                {"hkp://p80.pool.sks-keyservers.net:80"},
                {"http://p80.pool.sks-keyservers.net"},
                {"hkps://keyserver.ubuntu.com/"},
                {"hkps://hkps.pool.sks-keyservers.net"}
        };
    }

    @DataProvider(name = "badServerUrls")
    Object[][] badServerUrls() {
        return new Object[][]{
                {
                        "https://10.255.255.1:65535",
                        "java.io.IOException: Connect to 10.255.255.1:65535 [/10.255.255.1] failed: connect timed out " +
                                "for: https://10.255.255.1:65535",
                        true    // Should retry
                },
                {
                        "http://localhost:%d/sleep",
                        "java.io.IOException: Read timed out for: http://localhost:%d/sleep",
                        true    // Should retry
                },
                {
                        "http://localhost:%d/502",
                        "java.io.IOException: PGP server returned an error: HTTP/1.1 502 Bad Gateway for: http://localhost:%d/502",
                        true    // Should retry
                },
                {
                        "http://localhost:%d/404",
                        "org.simplify4u.plugins.keyserver.PGPKeyNotFound: PGP server returned an error: HTTP/1.1 404 Not Found for: http://localhost:%d/404",
                        false    // Should not retry
                }
        };
    }

    @BeforeClass
    public void setupMockServer() {
        mockServer = ClientAndServer.startClientAndServer(0);

        ConfigurationProperties.disableSystemOut(true);
        ConfigurationProperties.logLevel("WARNING");

        MockServerClient mockServerClient = new MockServerClient("localhost", mockServer.getLocalPort());

        mockServerClient
                .when(request().withPath("/sleep"))
                .respond(response()
                        .withStatusCode(200)
                        .withDelay(TimeUnit.SECONDS, 10));

        mockServerClient
                .when(request().withPath("/404"))
                .respond(response().withStatusCode(404));

        mockServerClient
                .when(request().withPath("/502"))
                .respond(response().withStatusCode(502));

        mavenSession = mock(MavenSession.class);
        when(mavenSession.getSettings()).thenReturn(mock(Settings.class));

    }

    @AfterClass(alwaysRun = true)
    public void cleanupMocServer() {
        mockServer.stop();
    }

    @Test(dataProvider = "goodServerUrls")
    public void testClient(String keyServerUrl) throws Exception {
        final File tempFile = File.createTempFile("PGPClientTest", null);

        tempFile.deleteOnExit();

        KeyServerClientSettings clientSettings = KeyServerClientSettings.builder()
                .mavenSession(mavenSession)
                .build();

        final PGPKeysServerClient client = PGPKeysServerClient.getClient(keyServerUrl, clientSettings);

        try (FileOutputStream outputStream = new FileOutputStream(tempFile)) {
            client.copyKeyToOutputStream(TEST_KEYID, outputStream, null);
        }

        assertTrue(tempFile.length() > 0, "Downloaded key was not expected to be empty");
    }

    @Test(dataProvider = "badServerUrls")
    public void testClientRetry(final String targetUrl,
            final String expectedExceptionString,
            final boolean shouldRetry) throws Exception {
        int maxRetries = 2;
        AtomicInteger attemptedRetries = new AtomicInteger(0);

        URI targetUri = new URI(String.format(targetUrl, mockServer.getLocalPort()));

        // We use short timeouts for both timeouts since we don't want to hold up the tests on URLs
        // we know will take a while.
        KeyServerClientSettings clientSettings = KeyServerClientSettings.builder()
                .mavenSession(mavenSession)
                .connectTimeout(SHORT_TEST_TIMEOUT)
                .readTimeout(SHORT_TEST_TIMEOUT)
                .maxRetries(maxRetries)
                .build();

        final PGPKeysServerClient client
                = new StubbedClient(targetUri, clientSettings);

        IOException caughtException = null;

        try (final ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            client.copyKeyToOutputStream(TEST_KEYID, outputStream,
                    (address, retry, waitInterval, exception) -> attemptedRetries.getAndIncrement());
        } catch (IOException ex) {
            caughtException = ex;
        }

        assertNotNull(caughtException);
        assertEquals(caughtException.toString().toUpperCase(),
                String.format(expectedExceptionString, mockServer.getLocalPort()).toUpperCase());

        if (shouldRetry) {
            assertEquals(attemptedRetries.get(), maxRetries);
        } else {
            assertEquals(attemptedRetries.get(), 0);
        }
    }

    /**
     * A special key client that allows the URL the client is requesting to be stubbed-out by tests.
     *
     * <p>This is used by tests that are testing retry behavior, to allow them to control exactly
     * which URL is being requested. Each URL provided by tests simulates a different type of failure.
     */
    private static class StubbedClient extends PGPKeysServerClientHttps {
        private final URI stubbedUri;

        StubbedClient(URI stubbedUri, KeyServerClientSettings clientSettings) throws IOException {
            super(stubbedUri, clientSettings);
            this.stubbedUri = stubbedUri;
        }

        @Override
        URI getUriForShowKey(KeyId keyID) {
            return this.stubbedUri;
        }

        @Override
        URI getUriForGetKey(KeyId keyID) {
            return this.stubbedUri;
        }
    }
}
