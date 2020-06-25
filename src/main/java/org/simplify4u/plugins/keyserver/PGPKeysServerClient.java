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
package org.simplify4u.plugins.keyserver;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;

import com.google.common.io.ByteStreams;
import io.github.resilience4j.core.IntervalFunction;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.event.RetryEvent;
import io.vavr.CheckedRunnable;
import io.vavr.control.Try;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.conn.routing.HttpRoutePlanner;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.ProxyAuthenticationStrategy;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.maven.settings.Proxy;
import org.simplify4u.plugins.utils.ExceptionUtils;
import org.simplify4u.plugins.utils.PGPKeyId;

/**
 * Abstract base client for requesting keys from PGP key servers over HKP/HTTP and HKPS/HTTPS.
 */
abstract class PGPKeysServerClient {

    private final Proxy proxy;

    @FunctionalInterface
    public interface OnRetryConsumer {
        void onRetry(InetAddress address, int numberOfRetryAttempts, Duration waitInterval, Throwable lastThrowable);
    }

    private static final int DEFAULT_CONNECT_TIMEOUT = 5000;
    private static final int DEFAULT_READ_TIMEOUT = 20000;
    public static final int DEFAULT_MAX_RETRIES = 10;

    private static final List<Class<? extends Throwable>> IGNORE_EXCEPTION_FOR_RETRY =
            Arrays.asList(PGPKeyNotFound.class, UnknownHostException.class);

    private final URI keyserver;
    private final int connectTimeout;
    private final int readTimeout;
    private final int maxAttempts;

    /**
     * Protected constructor for {@code PGPKeysServerClient}.
     *
     * @param keyserver
     *         The URI of the target key server.
     * @param connectTimeout
     *         The timeout (in milliseconds) that the client should wait to establish a connection to
     *         the PGP server.
     * @param readTimeout
     *         The timeout (in milliseconds) that the client should wait for data from the PGP server.
     * @param maxAttempts
     *         The maximum number of automatically retry request by client
     *
     * @see #getClient(String, Proxy)
     * @see #getClient(String, Proxy, int, int, int)
     */
    protected PGPKeysServerClient(URI keyserver, int connectTimeout, int readTimeout, int maxAttempts, Proxy proxy) {
        this.keyserver = keyserver;
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
        this.maxAttempts = maxAttempts;
        this.proxy = proxy;
    }

    /**
     * Create a PGP key server client for a given URL.
     *
     * @param keyServer
     *         The key server address / URL.
     *
     * @param proxy the proxy server to use (if any)
     * @return The right PGP client for the given address.
     */
    static PGPKeysServerClient getClient(String keyServer, Proxy proxy) throws IOException {
        return getClient(keyServer, proxy, DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT, DEFAULT_MAX_RETRIES);
    }

    /**
     * Create a PGP key server for a given URL.
     *
     * @param keyServer
     *         The key server address / URL.
     * @param proxy proxy server config
     * @param connectTimeout
     *         The timeout (in milliseconds) that the client should wait to establish a connection to
     *         the PGP server.
     * @param readTimeout
     *         The timeout (in milliseconds) that the client should wait for data from the PGP server.
     * @param maxAttempts
     *         The maximum number of automatically retry request by client
     *
     * @return The right PGP client for the given address.
     *
     * @throws IOException
     *         If some problem during client create.
     */
    static PGPKeysServerClient getClient(String keyServer, Proxy proxy,
            int connectTimeout, int readTimeout, int maxAttempts) throws IOException {
        final URI uri = Try.of(() -> new URI(keyServer))
                .getOrElseThrow((Function<Throwable, IOException>) IOException::new);

        final String protocol = uri.getScheme().toLowerCase(Locale.ROOT);

        switch (protocol) {
            case "hkp":
            case "http":
                return new PGPKeysServerClientHttp(uri, connectTimeout, readTimeout, maxAttempts, proxy);

            case "hkps":
            case "https":
                return new PGPKeysServerClientHttps(uri, connectTimeout, readTimeout, maxAttempts, proxy);

            default:
                throw new IOException("Unsupported protocol: " + protocol);
        }
    }

    private static String getQueryStringForGetKey(PGPKeyId keyID) {
        return String.format("op=get&options=mr&search=%s", keyID);
    }

    /**
     * Create URI for key download.
     *
     * @param keyID
     *         key ID
     *
     * @return URI with given key
     */
    URI getUriForGetKey(PGPKeyId keyID) {
        return Try.of(() -> new URI(keyserver.getScheme(), keyserver.getUserInfo(),
                keyserver.getHost(), keyserver.getPort(),
                "/pks/lookup", getQueryStringForGetKey(keyID), null)).get();
    }

    private static String getQueryStringForShowKey(PGPKeyId keyID) {
        return String.format("op=vindex&fingerprint=on&search=%s", keyID);
    }

    /**
     * Create URI for key lookup.
     *
     * @param keyID
     *         key ID
     *
     * @return URI with given key
     */
    URI getUriForShowKey(PGPKeyId keyID) {
        return Try.of(() -> new URI(keyserver.getScheme(), keyserver.getUserInfo(),
                keyserver.getHost(), keyserver.getPort(),
                "/pks/lookup", getQueryStringForShowKey(keyID), null)).get();
    }

    /**
     * Requests the PGP key with the specified key ID from the server and copies it to the specified
     * output stream.
     *
     * <p>If the request fails due to connectivity issues or server load, the request will be
     * retried automatically according to the configuration of the provided retry handler. If the
     * request still fails after exhausting retries, the final exception will be re-thrown.
     *
     * @param keyId
     *         The ID of the key to request from the server.
     * @param outputStream
     *         The output stream to which the key will be written.
     * @param onRetryConsumer
     *         The consumer which will be call on retry occurs
     *
     * @throws IOException
     *         If the request fails, or the key cannot be written to the output stream.
     */
    void copyKeyToOutputStream(PGPKeyId keyId, OutputStream outputStream, OnRetryConsumer onRetryConsumer)
            throws IOException {

        final URI keyUri = getUriForGetKey(keyId);
        final HttpUriRequest request = new HttpGet(keyUri);

        // use one instance of planer in order to remember failed hosts
        final HttpRoutePlanner planer = proxy == null ? new RoundRobinRouterPlaner() : getNewProxyRoutePlanner();

        RetryConfig config = RetryConfig.custom()
                .maxAttempts(maxAttempts)
                .waitDuration(Duration.ofMillis(500))
                .intervalFunction(IntervalFunction.ofExponentialBackoff())
                .retryOnException(PGPKeysServerClient::shouldRetryOnException)
                .build();

        Retry retry = Retry.of("id", config);

        retry.getEventPublisher()
                .onRetry(event -> processOnRetry(event, event.getWaitInterval(), planer, onRetryConsumer))
                .onError(event -> processOnRetry(event, Duration.ZERO, planer, onRetryConsumer));

        CheckedRunnable checkedRunnable = Retry.decorateCheckedRunnable(retry, () -> {
            try (final CloseableHttpClient client = this.buildClient(planer);
                 final CloseableHttpResponse response = client.execute(request)) {
                processKeyResponse(response, outputStream);
            }
        });

        try {
            checkedRunnable.run();
        } catch (PGPKeyNotFound e) {
            throw new PGPKeyNotFound("PGP server returned an error: HTTP/1.1 404 Not Found for: " + keyUri);
        } catch (Throwable e) {
            throw new IOException(ExceptionUtils.getMessage(e) + " for: " + keyUri, e);
        }
    }

    private HttpRoutePlanner getNewProxyRoutePlanner() {
        HttpHost httpHost = new HttpHost(proxy.getHost(), proxy.getPort());
        return new DefaultProxyRoutePlanner(httpHost);
    }

    private static boolean shouldRetryOnException(Throwable throwable) {

        Throwable aThrowable = throwable;
        while (aThrowable != null) {
            if (IGNORE_EXCEPTION_FOR_RETRY.contains(aThrowable.getClass())) {
                return false;
            }
            aThrowable = aThrowable.getCause();
        }
        return true;
    }

    private void processOnRetry(RetryEvent event, Duration waitInterval,
                                HttpRoutePlanner planer, OnRetryConsumer onRetryConsumer) {

        InetAddress targetAddress = null;
        if (planer instanceof RoundRobinRouterPlaner) {
            // inform planer about error on last roue
            HttpRoute httpRoute = ((RoundRobinRouterPlaner)planer).lastRouteCauseError();
            targetAddress = Try.of(() -> httpRoute.getTargetHost().getAddress()).getOrElse((InetAddress) null);
        } else if (proxy != null) {
            targetAddress = Try.of(() -> InetAddress.getByName(proxy.getHost())).getOrElse((InetAddress) null);
        }

        // inform caller about retry
        if (onRetryConsumer != null) {
            onRetryConsumer.onRetry(targetAddress, event.getNumberOfRetryAttempts(),
                    waitInterval, event.getLastThrowable());
        }
    }

    protected abstract HttpClientBuilder createClientBuilder();

    // abstract methods to implemented in child class.


    /**
     * Verify that the provided response was successful, and then copy the response to the given
     * output buffer.
     *
     * <p>If the response was not successful (e.g. not a "200 OK") status code, or the response
     * payload was empty, an {@link IOException} will be thrown.
     *
     * @param response
     *         A representation of the response from the server.
     * @param outputStream
     *         The stream to which the response data will be written.
     *
     * @throws IOException
     *         If the response was unsuccessful, did not contain any data, or could not be written
     *         completely to the target output stream.
     */
    private static void processKeyResponse(CloseableHttpResponse response, OutputStream outputStream)
            throws IOException {
        final StatusLine statusLine = response.getStatusLine();

        if (statusLine.getStatusCode() == HttpStatus.SC_NOT_FOUND) {
            throw new PGPKeyNotFound();
        }

        if (statusLine.getStatusCode() == HttpStatus.SC_OK) {
            final HttpEntity responseEntity = response.getEntity();

            if (responseEntity == null) {
                throw new IOException("No response body returned.");
            } else {
                try (InputStream inputStream = responseEntity.getContent()) {
                    ByteStreams.copy(inputStream, outputStream);
                }
            }
        } else {
            throw new IOException("PGP server returned an error: " + statusLine);
        }
    }

    /**
     * Build an HTTP client with the given router planer.
     *
     * @param planer
     *         The router planer for http client, used for load balancing
     *
     * @return The new HTTP client instance.
     */
    private CloseableHttpClient buildClient(HttpRoutePlanner planer) {


        final HttpClientBuilder clientBuilder = this.createClientBuilder();

        this.applyTimeouts(clientBuilder);
        clientBuilder.setRoutePlanner(planer);

        return clientBuilder.build();
    }

    /**
     * Set connect and read timeouts for an HTTP client that is being built.
     *
     * @param builder
     *         The client builder to which timeouts will be applied.
     */
    private void applyTimeouts(final HttpClientBuilder builder) {
        final RequestConfig requestConfig =
                RequestConfig
                        .custom()
                        .setConnectionRequestTimeout(this.connectTimeout)
                        .setConnectTimeout(this.connectTimeout)
                        .setSocketTimeout(this.readTimeout)
                        .build();

        builder.setDefaultRequestConfig(requestConfig);
    }

    protected HttpClientBuilder setupProxy(HttpClientBuilder clientBuilder) {
        if (this.proxy == null) {
            return clientBuilder;
        }

        if (proxy.getUsername() != null && !proxy.getUsername().isEmpty() &&
            proxy.getPassword() != null && !proxy.getPassword().isEmpty()) {
            clientBuilder.setProxyAuthenticationStrategy(ProxyAuthenticationStrategy.INSTANCE);
            BasicCredentialsProvider basicCredentialsProvider = new BasicCredentialsProvider();
            AuthScope proxyAuthScope = new AuthScope(proxy.getHost(), proxy.getPort());
            UsernamePasswordCredentials proxyAuthentication =
                new UsernamePasswordCredentials(proxy.getUsername(), proxy.getPassword());
            basicCredentialsProvider.setCredentials(proxyAuthScope, proxyAuthentication);
            clientBuilder.setDefaultCredentialsProvider(basicCredentialsProvider);
        }
        return clientBuilder;
    }

    @Override
    public String toString() {
        return "{" + keyserver + "}";
    }
}

