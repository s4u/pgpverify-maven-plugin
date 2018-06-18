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
 * (timeouts, 408 errors, and some 5XX errors).
 *
 * <p>By default, this strategy will allow retrying up to ten times before
 * giving up. The maximum number of retries can be controlled by using the
 * {@link #TransientFailureRetryStrategy(int)} constructor.
 *
 * <p>Instances of this strategy maintain a retry counter. For this reason,
 * after a request has been completed, the same failure strategy instance should
 * not be used for any subsequent requests. A new failure strategy instance
 * should be created for each new request (excluding retries of the same
 * request).
 */
public class TransientFailureRetryStrategy extends BackoffStrategy {
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
                HttpURLConnection.HTTP_CLIENT_TIMEOUT,
                HttpURLConnection.HTTP_INTERNAL_ERROR,
                HttpURLConnection.HTTP_BAD_GATEWAY,
                HttpURLConnection.HTTP_UNAVAILABLE,
                HttpURLConnection.HTTP_GATEWAY_TIMEOUT
            ));

    /**
     * Constructor for {@code TransientFailureRetryStrategy}.
     *
     * <p>Creates a retry strategy that will allow retrying the same request up
     * to ten times.
     */
    public TransientFailureRetryStrategy() {
        super(DEFAULT_BACKOFF_SCALAR, DEFAULT_MAX_RETRY_COUNT);
    }

    /**
     * Constructor for {@code TransientFailureRetryStrategy}.
     *
     * <p>Creates a retry strategy that will allow retrying the same request up
     * to the specified number of times.
     *
     * @param maxRetryCount
     *   The maximum number of times that the request can be retried.
     */
    public TransientFailureRetryStrategy(final int maxRetryCount) {
        super(DEFAULT_BACKOFF_SCALAR, maxRetryCount);
    }

    /**
     * Constructor for {@code TransientFailureRetryStrategy}.
     *
     * <p>Creates a retry strategy that will allow retrying the same request up
     * to the specified number of times, with the specified number of milliseconds of delay added to
     * each additional attempt. For example, {@code 500} would cause the first retry to happen
     * half a second later, the second retry one second later, the third one and a half seconds
     * later, and so on.
     *
     * @param backoffScalar
     *   The number of milliseconds to add to each retry attempt. The delay is cumulative, so each
     *   retry takes longer than the previous one.
     * @param maxRetryCount
     *   The maximum number of times that the request can be retried.
     */
    public TransientFailureRetryStrategy(int backoffScalar, int maxRetryCount) {
        super(backoffScalar, maxRetryCount);
    }

    @Override
    public boolean canRetry(final URL url, final URLConnection connection,
                            final IOException cause) {
        return super.canRetry(url, connection, cause)
            && (canRetryExceptionType(cause) || canRetryStatusCode(connection));
    }

    private boolean canRetryExceptionType(final IOException cause) {
        for (Class<? extends IOException> exceptionType : RETRYABLE_EXCEPTION_TYPES) {
            if (exceptionType.isInstance(cause)) {
                return true;
            }
        }

        return false;
    }

    @SuppressWarnings("PMD.EmptyCatchBlock")
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
