/*
 * Copyright 2017 Slawomir Jaranowski
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
package org.simplify4u.plugins;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import org.apache.http.protocol.HttpContext;
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class PGPKeysServerClientIT {
    private static final long TEST_KEYID = 0xF8484389379ACEACL;

    private static final int SHORT_TEST_TIMEOUT = 1000;

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
                "org.apache.http.conn.ConnectTimeoutException: Connect to 10.255.255.1:65535 "
                + "[/10.255.255.1] failed: connect timed out",
                true    // Should retry
            },
            {
                "https://httpstat.us/200?sleep=10000",
                "java.net.SocketTimeoutException: Read timed out",
                true    // Should retry
            },
            {
                "https://httpstat.us/502",
                "java.io.IOException: PGP server returned an error: HTTP/1.1 502 Bad Gateway",
                true    // Should retry
            },
            {
                "https://httpstat.us/404",
                "java.io.IOException: PGP server returned an error: HTTP/1.1 404 Not Found",
                false    // Should not retry
            }
        };
    }

    @BeforeClass
    public void suppressApacheLogging() {
        System.setProperty(
            "org.apache.commons.logging.Log",
            "org.apache.commons.logging.impl.SimpleLog");

        System.setProperty(
            "org.apache.commons.logging.simplelog.log.org.apache.http",
            "ERROR");
    }

    @Test(dataProvider = "goodServerUrls")
    public void testClient(String keyServerUrl) throws Exception {
        final File tempFile = File.createTempFile("PGPClientTest", null);

        tempFile.deleteOnExit();

        final PGPKeysServerClient client = PGPKeysServerClient.getClient(keyServerUrl);

        try (FileOutputStream outputStream = new FileOutputStream(tempFile)) {
            client.copyKeyToOutputStream(
                TEST_KEYID,
                outputStream,
                new PGPServerRetryHandler(
                    new SystemStreamLog(),
                    PGPServerRetryHandler.DEFAULT_MAX_RETRIES,
                    PGPServerRetryHandler.DEFAULT_BACKOFF_INTERVAL));
        }

        assertTrue(tempFile.length() > 0, "Downloaded key was not expected to be empty");
    }

    @Test(dataProvider = "badServerUrls")
    public void testClientRetry(final String targetUrl,
                                final String expectedExceptionString,
                                final boolean shouldRetry)
    throws Exception {
        final int maxRetries = 2;
        final AtomicInteger attemptedRetries = new AtomicInteger(0);

        final PGPServerRetryHandler retryHandler = new PGPServerRetryHandler(maxRetries) {
            @Override
            protected void onRetry(final String retryReason, final int retryCount,
                                   final long backoffDelay, final HttpContext requestContext) {
                attemptedRetries.incrementAndGet();
            }
        };

        // We use short timeouts for both timeouts since we don't want to hold up the tests on URLs
        // we know will take a while.
        final PGPKeysServerClient client
            = new StubbedClient(new URI(targetUrl), SHORT_TEST_TIMEOUT, SHORT_TEST_TIMEOUT);

        IOException caughtException = null;

        try (final ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            client.copyKeyToOutputStream(TEST_KEYID, outputStream, retryHandler);
        } catch (IOException ex) {
            caughtException = ex;
        }

        assertNotNull(caughtException);
        assertEquals(caughtException.toString(), expectedExceptionString);

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
     * which URL is being requested. Each URL provided by tests simulates a different type of
     * failure.
     */
    private static class StubbedClient
    extends PGPKeysServerClientHttps {
        private final URI stubbedUri;

        StubbedClient(final URI stubbedUri, final int connectTimeout, final int readTimeout)
        throws CertificateException, NoSuchAlgorithmException, IOException, KeyManagementException,
               KeyStoreException, URISyntaxException {
            super(stubbedUri, connectTimeout, readTimeout);

            this.stubbedUri = stubbedUri;
        }

        @Override
        URI getUriForShowKey(long keyID) {
            return this.stubbedUri;
        }

        @Override
        URI getUriForGetKey(long keyID) {
            return this.stubbedUri;
        }
    }
}
