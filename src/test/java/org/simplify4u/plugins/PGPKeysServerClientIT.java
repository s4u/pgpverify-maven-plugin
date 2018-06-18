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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Date;
import org.simplify4u.plugins.failurestrategies.TransientFailureRetryStrategy;
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
            {"hkps://pgp.mit.edu/"},
            {"hkps://hkps.pool.sks-keyservers.net"}
        };
    }

    @DataProvider(name = "badServerUrls")
    Object[][] badServerUrls() {
        return new Object[][]{
            {
                "https://example.com:81",
                "java.net.SocketTimeoutException: connect timed out",
                true    // Should retry
            },
            {
                "https://httpstat.us/200?sleep=10000",
                "java.net.SocketTimeoutException: Read timed out",
                true    // Should retry
            },
            {
                "https://httpstat.us/502",
                "java.io.IOException: Server returned HTTP response code: 502 for URL: "
                + "https://httpstat.us/502",
                true    // Should retry
            },
            {
                "https://httpstat.us/404",
                "java.io.FileNotFoundException: https://httpstat.us/404",
                false    // Should not retry
            }
        };
    }

    @Test(dataProvider = "goodServerUrls", successPercentage = 80)
    public void testClient(String keyServerUrl) throws Exception {
        final File tempFile = File.createTempFile("PGPClientTest", null);

        tempFile.deleteOnExit();

        final PGPKeysServerClient client = PGPKeysServerClient.getClient(keyServerUrl);

        try (FileOutputStream outputStream = new FileOutputStream(tempFile)) {
            client.copyKeyToOutputStream(TEST_KEYID, outputStream, new VerboseRetryStrategy());
        }

        assertTrue(tempFile.length() > 0, "Downloaded key was not expected to be empty");
    }

    @Test(dataProvider = "badServerUrls")
    public void testClientRetry(final String targetUrl,
                                final String expectedExceptionString,
                                final boolean shouldRetry)
    throws Exception {
        final int maxRetries = 2;
        final TransientFailureRetryStrategy retryStrategy
            = new TransientFailureRetryStrategy(100, maxRetries);

        // We use short timeouts for both timeouts since we don't want to hold up the tests on URLs
        // we know will take a while.
        final PGPKeysServerClient client
            = new StubbedClient(new URI(targetUrl), SHORT_TEST_TIMEOUT, SHORT_TEST_TIMEOUT);

        IOException caughtException = null;

        try (final ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            client.copyKeyToOutputStream(TEST_KEYID, outputStream, retryStrategy);

            System.out.println(new String(outputStream.toByteArray()));
        } catch (IOException ex) {
            caughtException = ex;
        }

        assertNotNull(caughtException);
        assertEquals(caughtException.toString(), expectedExceptionString);

        if (shouldRetry) {
            assertEquals(retryStrategy.getCurrentRetryCount(), maxRetries);
        } else {
            assertEquals(retryStrategy.getCurrentRetryCount(), 0);
        }
    }

    /**
     * This retry strategy is used for tests against real key servers.
     *
     * <p>This extends the normal transient failure retry strategy to provide additional output to
     * standard error when a key server is triggering a retry, since this should be a rare event --
     * unless the server is unreliable. The additional output is intended to help nail down the
     * issue.
     */
    private static class VerboseRetryStrategy
    extends TransientFailureRetryStrategy {
        private Date lastRetryStart;

        VerboseRetryStrategy() {
            super();

            this.resetTimer();
        }

        @Override
        public void onRetry(URL url, IOException cause) {
            super.onRetry(url, cause);

            System.err.println(
                String.format(
                    "[Retry %d of %d] Attempting key request from %s after error "
                    + "(failed after %d seconds, target host was %s): \"%s\"",
                    this.getCurrentRetryCount(),
                    this.getMaxRetryCount(),
                    url,
                    this.getSecondsSinceLastRetry(),
                    this.getTargetHost(url),
                    cause.toString()));

            this.resetTimer();
        }

        private String getTargetHost(URL url) {
            String ipAddress;

            final InetAddress address;
            try {
                address = InetAddress.getByName(url.getHost());
                ipAddress = address.toString();
            } catch (UnknownHostException ex) {
                // Suppress -- fall back to "unknown".
                ipAddress = "unknown";
            }

            return ipAddress;
        }

        @Override
        public void onBackoff(final URL url, final long delay) {
            super.onBackoff(url, delay);

            System.err.println(
                String.format(
                    "[Retry %d of %d] Backing off for %d milliseconds...",
                    this.getCurrentRetryCount(),
                    this.getMaxRetryCount(),
                    delay));
        }

        private void resetTimer() {
            this.lastRetryStart = new Date();
        }

        private long getSecondsSinceLastRetry() {
            final Date now = new Date();

            return (now.getTime() - this.lastRetryStart.getTime()) / 1000;
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
