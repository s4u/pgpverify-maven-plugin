/*
 * Copyright 2018 Wren Security
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

import com.google.common.collect.ImmutableList;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLException;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.ServiceUnavailableRetryStrategy;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.apache.http.util.Args;
import org.apache.maven.plugin.logging.Log;

/**
 * The primary handler for retry logic in HKP/HTTP and HKPS/HTTPS clients in this plug-in.
 *
 * <p>This handler is a composite of the following two interfaces:
 * <ul>
 *     <li>A {@link HttpRequestRetryHandler}, which controls how retries are handled for service
 *     reach-ability (e.g. connection timeouts, connection drops).</li>
 *     <li>A {@link ServiceUnavailableRetryStrategy}, which controls how retries are handled for
 *     service load issues (e.g. internal server errors, load balancer errors, read timeouts,
 *     etc).</li>
 * </ul>
 *
 * <p>The handler unifies the two interfaces, providing a single injection point for logging and
 * retry handling.
 */
public class PGPServerRetryHandler
implements HttpRequestRetryHandler, ServiceUnavailableRetryStrategy {
    /**
     * The maximum number of retry attempts that either handler will make before giving up.
     *
     * <p>This default applies to each type of handler. This means that if both are configured with
     * the default value, then it is conceivable that the same request could hypothetically be
     * retried up to 20 times (10 times for connection issues, then 10 times upon connecting and
     * repeatedly receiving a bad HTTP response).
     */
    public static final int DEFAULT_MAX_RETRIES = 10;

    /**
     * The amount of time added to each additional retry attempt.
     *
     * <p>The interval is additive. For example, if there are three retry attempts, the first will
     * occur after 750 milliseconds; the second will occur after 1,500 milliseconds; and the third
     * will occur after 2,250 milliseconds.
     */
    public static final int DEFAULT_BACKOFF_INTERVAL = 750;

    private final RequestRetryStrategy requestRetryHandler;
    private final ServiceRetryStrategy serviceRetryHandler;
    private final Log logger;

    /**
     * Default constructor for {@code PGPServerRetryHandler}.
     *
     * <p>The handler is constructed to perform up to {@link #DEFAULT_MAX_RETRIES} retries, backing
     * off an additional {@link #DEFAULT_BACKOFF_INTERVAL}milliseconds in between each attempt;
     * without any logging output.
     */
    public PGPServerRetryHandler() {
        this(DEFAULT_MAX_RETRIES);
    }

    /**
     * Constructor for a {@code PGPServerRetryHandler} that writes to the given logger.
     *
     * <p>The handler is constructed to perform up to {@link #DEFAULT_MAX_RETRIES} retries, backing
     * off an additional {@link #DEFAULT_BACKOFF_INTERVAL}milliseconds in between each attempt.
     * Warnings are written out to the logger whenever retries are being attempted.
     *
     * @param logger
     *   The logger to which output will be written.
     */
    public PGPServerRetryHandler(final Log logger) {
        this(logger, DEFAULT_MAX_RETRIES, DEFAULT_BACKOFF_INTERVAL);
    }

    /**
     * Constructor for a {@code PGPServerRetryHandler} that performs up to a set number of retries.
     *
     * <p>The handler is constructed to perform up to {@code maxRetries} retries, backing off an
     * additional {@link #DEFAULT_BACKOFF_INTERVAL}milliseconds in between each attempt; without any
     * logging output.
     *
     * @param maxRetries
     *   The maximum number of times to retry on service reach-ability or server load issues.
     */
    public PGPServerRetryHandler(int maxRetries) {
        this(new NullLogger(), maxRetries, DEFAULT_BACKOFF_INTERVAL);
    }

    /**
     * Constructor for a {@code PGPServerRetryHandler} that performs up to a set number of retries
     * and writes to the given logger.
     *
     * <p>The handler is constructed to perform up to {@code maxRetries} retries, backing off an
     * additional {@code backoffInterval} milliseconds in between each attempt. Warnings are written
     * out to the logger whenever retries are being attempted.
     *
     * @param logger
     *   The logger to which output will be written.
     * @param maxRetries
     *   The maximum number of times to retry on service reach-ability or server load issues.
     * @param backoffInterval
     *   The additional number of milliseconds of delay to add to each additional retry attempt.
     */
    public PGPServerRetryHandler(final Log logger, final int maxRetries,
                                 final long backoffInterval) {
        this.requestRetryHandler = new RequestRetryStrategy(maxRetries);
        this.serviceRetryHandler = new ServiceRetryStrategy(maxRetries, backoffInterval);
        this.logger = logger;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Unlike the default Apache implementation of this method, this handler enforces a back-off
     * delay before allowing the retry to proceed. This helps to ensure that PGP servers are given
     * an opportunity to recover from server-side load issues.
     */
    @Override
    public boolean retryRequest(final IOException cause,
                                final int executionCount,
                                final HttpContext requestContext) {
        final boolean shouldRetry
            = this.requestRetryHandler.retryRequest(cause, executionCount, requestContext);

        final long backoffDelay = this.serviceRetryHandler.getBackoffScalar() * executionCount;

        this.dispatchRetry(
            shouldRetry,
            cause.toString(),
            executionCount,
            backoffDelay,
            requestContext);

        if (shouldRetry && backoffDelay > 0) {
            // Add a back-off strategy to request retries to avoid overwhelming PGP servers.
            try {
                Thread.sleep(backoffDelay);
            } catch (InterruptedException ex) {
                throw new IllegalStateException("Interrupted during request back-off", ex);
            }
        }

        return shouldRetry;
    }

    @Override
    public boolean retryRequest(final HttpResponse errorResponse, final int executionCount,
                                final HttpContext requestContext) {
        final boolean shouldRetry
            = this.serviceRetryHandler.retryRequest(errorResponse, executionCount, requestContext);

        this.dispatchRetry(
            shouldRetry,
            errorResponse.getStatusLine().toString(),
            executionCount,
            this.getRetryInterval(),
            requestContext);

        return shouldRetry;
    }

    @Override
    public long getRetryInterval() {
        return this.serviceRetryHandler.getRetryInterval();
    }

    /**
     * An injection point for sub-classes to invoke their own logic each time a retry is attempted.
     *
     * @param retryReason
     *   A human-friendly description of the reason for why the retry is being attempted.
     * @param retryCount
     *   A count of the number of retries that have been attempted. The value is one-based, so the
     *   first retry has a {@code retryCount} of {@code 1}.
     * @param backoffDelay
     *   The total number of milliseconds that the client will delay before the retry attempt
     *   will occur. This method is invoked just prior to the start of this interval.
     * @param requestContext
     *   Client context about the prior, failed request that was previously attempted.
     */
    protected void onRetry(final String retryReason, final int retryCount,
                           final long backoffDelay, final HttpContext requestContext) {
        // No-op -- provided for sub-classes to override
    }

    /**
     * Dispatch the appropriate events to sub-classes and the logger if a try should be attempted.
     *
     * @param shouldRetry
     *   Whether or not the underlying handler indicated that a retry should be attempted.
     * @param retryReason
     *   A human-friendly description of the reason for why the retry is being attempted.
     * @param retryCount
     *   A count of the number of retries that have been attempted. The value is one-based, so the
     *   first retry has a {@code retryCount} of {@code 1}.
     * @param backoffDelay
     *   The total number of milliseconds that the client will delay before the retry attempt
     *   will occur. This method is invoked just prior to the start of this interval.
     * @param requestContext
     *   Client context about the prior, failed request that was previously attempted.
     */
    private void dispatchRetry(boolean shouldRetry, final String retryReason,
                               final int retryCount, final long backoffDelay,
                               final HttpContext requestContext) {
        if (shouldRetry) {
            this.logRetry(retryReason, retryCount, backoffDelay, requestContext);
            this.onRetry(retryReason, retryCount, backoffDelay, requestContext);
        }
    }

    /**
     * Write a warning to the logger that includes information about a request is about to be
     * retried.
     *
     * @param retryReason
     *   A human-friendly description of the reason for why the retry is being attempted.
     * @param retryCount
     *   A count of the number of retries that have been attempted. The value is one-based, so the
     *   first retry has a {@code retryCount} of {@code 1}.
     * @param backoffDelay
     *   The total number of milliseconds that the client will delay before the retry attempt
     *   will occur. This method is invoked just prior to the start of this interval.
     * @param requestContext
     *   Client context about the prior, failed request that was previously attempted.
     */
    private void logRetry(final String retryReason, final int retryCount,
                          final long backoffDelay, final HttpContext requestContext) {
        final HttpHost host =
            (HttpHost) requestContext.getAttribute(HttpCoreContext.HTTP_TARGET_HOST);

        if (logger.isWarnEnabled()) {
            logger.warn(
                String.format(
                    "[Retry %d of %d] Waiting %d milliseconds before retrying key request from %s "
                    + "after last request failed: %s",
                    retryCount,
                    this.requestRetryHandler.getRetryCount(),
                    backoffDelay,
                    describeHost(host),
                    retryReason));
        }
    }

    /**
     * Convert an Apache HTTP host object to a human-readable, loggable description of the host.
     *
     * @param host
     *   The host to convert to loggable output.
     *
     * @return
     *   The human-readable, loggable description of the host, including the hostname and IP
     *   address.
     */
    private String describeHost(final HttpHost host) {
        String description;

        try {
            InetAddress address = host.getAddress();

            if (address == null) {
                address = InetAddress.getByName(host.getHostName());
            }

            description = address.toString();
        } catch (UnknownHostException ex) {
            // Suppress -- fall back to "unknown".
            description = "(unknown)";
        }

        return description;
    }

    /**
     * The inner request retry strategy that the outer class wraps.
     *
     * <p>This controls how retries are handled for service reach-ability (e.g. connection
     * timeouts, connection drops). It is invoked whenever a connection cannot be established or is
     * dropped, without a complete response.
     */
    private static class RequestRetryStrategy
    extends DefaultHttpRequestRetryHandler {
        /**
         * The types of HTTP exceptions that are not worth retrying.
         */
        @SuppressWarnings("unchecked")
        private static final List<Class<? extends IOException>> IGNORED_EXCEPTIONS =
            (List) Collections.singletonList(SSLException.class);

        /**
         * Constructor for {@code RequestRetryStrategy}.
         *
         * @param maxRetries
         *   The maximum number of times to retry connecting to a service.
         */
        RequestRetryStrategy(final int maxRetries) {
            super(maxRetries, false, IGNORED_EXCEPTIONS);

            Args.positive(maxRetries, "Max retries");
        }
    }

    /**
     * The inner service retry strategy that the outer class wraps.
     *
     * <p>This controls how retries are handled for service load issues (e.g. internal server
     * errors, load balancer errors, read timeouts, etc). This handler is invoked when there has
     * been an unsuccessful response returned by the target server.
     */
    private static class ServiceRetryStrategy
    implements ServiceUnavailableRetryStrategy {
        /**
         * The list of HTTP status codes that signal request failures that may be recoverable after
         * a retry.
         */
        private static final List<Integer> RETRYABLE_STATUS_CODES =
            ImmutableList.of(
                HttpStatus.SC_REQUEST_TIMEOUT,
                HttpStatus.SC_INTERNAL_SERVER_ERROR,
                HttpStatus.SC_BAD_GATEWAY,
                HttpStatus.SC_SERVICE_UNAVAILABLE,
                HttpStatus.SC_GATEWAY_TIMEOUT
            );

        /**
         * Maximum number of allowed retries if the server responds with a HTTP code
         * in our retry code list.
         */
        private final int maxRetries;

        /**
         * The number of milliseconds to add to each retry attempt. The delay is cumulative, so each
         * retry takes this much longer than the previous one.
         */
        private final long backoffScalar;

        /**
         * The number of times that this strategy has been asked to retry so far.
         */
        private final AtomicLong currentRetryCount;

        /**
         * Constructor for {@code ServiceRetryStrategy}.
         *
         * @param maxRetries
         *   The maximum number of allowed retries if the server responds with a HTTP code in our
         *   retry code list.
         * @param backoffScalar
         *   The number of milliseconds to add to each retry attempt. The delay is cumulative, so
         *   each retry takes this much longer than the previous one.
         */
        ServiceRetryStrategy(final int maxRetries, final long backoffScalar) {
            super();

            Args.positive(maxRetries, "Max retries");
            Args.positive(backoffScalar, "Back-off scalar interval");

            this.maxRetries = maxRetries;
            this.backoffScalar = backoffScalar;
            this.currentRetryCount = new AtomicLong(0);
        }

        /**
         * Get the number of milliseconds to add to each retry attempt. The delay is cumulative, so
         * each retry should takes this much longer than the previous one.
         *
         * @return
         *   The number of milliseconds to add to each retry request.
         */
        public long getBackoffScalar() {
            return this.backoffScalar;
        }

        @Override
        public boolean retryRequest(final HttpResponse response, final int executionCount,
                                    final HttpContext context) {
            final boolean shouldRetry
                = executionCount <= maxRetries
                && RETRYABLE_STATUS_CODES.contains(response.getStatusLine().getStatusCode());

            if (shouldRetry) {
                this.currentRetryCount.incrementAndGet();
            }

            return shouldRetry;
        }

        /**
         * {@inheritDoc}
         *
         * <p>The interval is cumulative, so each retry attempt should take longer than the previous
         * one.
         *
         * @see #getBackoffScalar()
         */
        @Override
        public long getRetryInterval() {
            return this.currentRetryCount.get() * this.backoffScalar;
        }
    }
}
