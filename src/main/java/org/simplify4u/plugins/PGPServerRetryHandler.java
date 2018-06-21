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

public class PGPServerRetryHandler
implements HttpRequestRetryHandler, ServiceUnavailableRetryStrategy {
    public static final int DEFAULT_MAX_RETRIES = 10;
    public static final int DEFAULT_BACKOFF_INTERVAL = 750;

    private final RequestRetryStrategy requestRetryHandler;
    private final ServiceRetryStrategy serviceRetryHandler;
    private final Log logger;

    public PGPServerRetryHandler() {
        this(new NullLogger(), DEFAULT_MAX_RETRIES, DEFAULT_BACKOFF_INTERVAL);
    }

    public PGPServerRetryHandler(final Log logger) {
        this(logger, DEFAULT_MAX_RETRIES, DEFAULT_BACKOFF_INTERVAL);
    }

    public PGPServerRetryHandler(int maxRetries) {
        this(new NullLogger(), maxRetries, DEFAULT_BACKOFF_INTERVAL);
    }

    public PGPServerRetryHandler(final Log logger, final int maxRetries,
                                 final long unavailableBackoffInterval) {
        this.requestRetryHandler = new RequestRetryStrategy(maxRetries);
        this.serviceRetryHandler = new ServiceRetryStrategy(maxRetries, unavailableBackoffInterval);
        this.logger = logger;
    }

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

    protected void onRetry(final String retryReason, final int retryCount,
                           final long backoffDelay, final HttpContext requestContext) {
        // No-op -- provided for sub-classes to override
    }

    private void dispatchRetry(boolean shouldRetry, final String retryReason,
                               final int executionCount, final long backoffDelay,
                               final HttpContext requestContext) {
        if (shouldRetry) {
            this.logRetry(retryReason, executionCount, backoffDelay, requestContext);
            this.onRetry(retryReason, executionCount, backoffDelay, requestContext);
        }
    }

    private void logRetry(final String retryReason, final int executionCount,
                          final long backoffDelay, final HttpContext context) {
        final HttpHost host = (HttpHost) context.getAttribute(HttpCoreContext.HTTP_TARGET_HOST);

        if (logger.isWarnEnabled()) {
            logger.warn(
                String.format(
                    "[Retry %d of %d] Waiting %d milliseconds before retrying key request from %s "
                    + "after last request failed: %s",
                    executionCount,
                    this.requestRetryHandler.getRetryCount(),
                    backoffDelay,
                    describeHost(host),
                    retryReason));
        }
    }

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

    private static class RequestRetryStrategy
    extends DefaultHttpRequestRetryHandler {
        @SuppressWarnings("unchecked")
        private static final List<Class<? extends IOException>> IGNORED_EXCEPTIONS =
            (List) Collections.singletonList(SSLException.class);

        RequestRetryStrategy(final int maxRetries) {
            super(maxRetries, false, IGNORED_EXCEPTIONS);
        }
    }

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
         * in our retry code list. Default value is 1.
         */
        private final int maxRetries;

        /**
         * The number of milliseconds to add to each retry attempt. The delay is cumulative, so each
         * retry takes longer than the previous one.
         */
        private final long backoffScalar;

        /**
         * The number of times that this strategy has been asked to retry so far.
         */
        private final AtomicLong currentRetryCount;

        ServiceRetryStrategy(final int maxRetries, final long backoffScalar) {
            super();

            Args.positive(maxRetries, "Max retries");
            Args.positive(backoffScalar, "Back-off scalar interval");

            this.maxRetries = maxRetries;
            this.backoffScalar = backoffScalar;
            this.currentRetryCount = new AtomicLong(0);
        }

        public long getBackoffScalar() {
            return backoffScalar;
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

        @Override
        public long getRetryInterval() {
            return this.currentRetryCount.get() * this.backoffScalar;
        }
    }
}
