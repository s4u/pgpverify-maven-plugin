/*
 * Copyright 2018 Wren Security.
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

package org.simplify4u.plugins.failurestrategies;

import java.io.IOException;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * A failure strategy that automatically retries transient HTTP failures
 * (timeouts and some 5XX errors).
 *
 * <p>By default, this strategy will allow retrying up to four times before
 * giving up. The maximum number of retries can be controlled by using the
 * {@link #TransientFailureRetryStrategy(int)} constructor.
 *
 * <p>Instances of this strategy maintain a retry counter. For this reason,
 * after a request has been completed, the same failure strategy instance should
 * not be used for any subsequent requests. A new failure strategy instance
 * should be created for each new request (excluding retries of the same
 * request).
 */
public class TransientFailureRetryStrategy extends RetryNTimesStrategy {
    /**
     * The list of exception types that signal request failures that may recover after a retry.
     */
    private static final List<Class<? extends IOException>> RETRYABLE_EXCEPTION_TYPES =
        Collections.unmodifiableList(
            Arrays.asList(
                ConnectException.class,
                SocketTimeoutException.class
            ));

    /**
     * The list of HTTP status codes that signal request failures that may recover after a retry.
     */
    private static final List<Integer> RETRYABLE_STATUS_CODES =
        Collections.unmodifiableList(
            Arrays.asList(
                HttpURLConnection.HTTP_INTERNAL_ERROR,
                HttpURLConnection.HTTP_BAD_GATEWAY,
                HttpURLConnection.HTTP_UNAVAILABLE,
                HttpURLConnection.HTTP_GATEWAY_TIMEOUT
            ));

    /**
     * Constructor for {@code TransientFailureRetryStrategy}.
     *
     * <p>Creates a retry strategy that will allow retrying the same request up
     * to four times.
     */
    public TransientFailureRetryStrategy() {
        this(DEFAULT_MAX_RETRY_COUNT);
    }

    /**
     * Constructor for {@code TransientFailureRetryStrategy}.
     *
     * <p>Creates a retry strategy that will allow retrying the same request up
     * to the specified number of times.
     */
    public TransientFailureRetryStrategy(final int maxRetryCount) {
        super(maxRetryCount);
    }

    @Override
    public boolean canRetry(final URL url, final URLConnection connection,
                            final IOException cause) {
        return super.canRetry(url, connection, cause)
            && (canRetryExceptionType(cause) || canRetryStatusCode(connection));
    }

    private boolean canRetryExceptionType(final IOException cause) {
        return RETRYABLE_EXCEPTION_TYPES
            .stream()
            .anyMatch((exceptionType) -> exceptionType.isInstance(cause));
    }

    private boolean canRetryStatusCode(URLConnection connection) {
        boolean canRetry = false;

        if (connection instanceof HttpURLConnection) {
            try {
                final int responseCode = ((HttpURLConnection) connection).getResponseCode();

                canRetry = RETRYABLE_STATUS_CODES.contains(responseCode);
            } catch (IOException ex) {
                // Should not happen -- by now we should have the status code.
                // In this case, we assume we cannot retry.
            }
        }

        return canRetry;
    }
}
