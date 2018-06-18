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
import java.net.URL;

/**
 * A failure strategy that will retry up to N times, backing off a longer period of time between
 * attempts to allow the target server to recover.
 *
 * <p>By default, this strategy will allow retrying up to four times, with an additional 500
 * milliseconds more per attempt, before giving up. The maximum number of retries can be controlled
 * by using the {@link #BackoffStrategy(int)} constructor.
 *
 * <p>As expected, instances of this strategy maintain a retry counter. For this
 * reason, after a request has been completed, the same failure strategy
 * instance should not be used for a subsequent request. A new failure strategy
 * instance should be created for each new request (excluding retries of the
 * same request).
 */
public class BackoffStrategy extends RetryNTimesStrategy {
    public static final int DEFAULT_BACKOFF_SCALAR = 500;

    private final int backoffScalar;

    /**
     * Constructor for {@code BackoffStrategy}.
     *
     * <p>Creates a retry strategy that will allow retrying the same request up
     * to four times.
     */
    public BackoffStrategy() {
        this(DEFAULT_MAX_RETRY_COUNT, DEFAULT_BACKOFF_SCALAR);
    }

    /**
     * Constructor for {@code BackoffStrategy}.
     *
     * <p>Creates a retry strategy that will allow retrying the same request up to four times, with
     * the specified number of milliseconds of delay added to each additional attempt. For example,
     * {@code 500} would cause the first retry to happen half a second later, the second retry one
     * second later, the third one and a half seconds later, and so on.
     *
     * @param backoffScalar
     *   The number of milliseconds to add to each retry attempt. The delay is cumulative, so each
     *   retry takes longer than the previous one.
     */
    public BackoffStrategy(int backoffScalar) {
        this(backoffScalar, DEFAULT_MAX_RETRY_COUNT);
    }

    /**
     * Constructor for {@code BackoffStrategy}.
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
    public BackoffStrategy(int backoffScalar, int maxRetryCount) {
        super(maxRetryCount);

        this.backoffScalar = backoffScalar;
    }

    @Override
    public void onRetry(URL url, IOException cause) {
        super.onRetry(url, cause);

        try {
            Thread.sleep(this.getCurrentRetryCount() * backoffScalar);
        } catch (InterruptedException ex) {
            throw new IllegalStateException("Interrupted during retry", ex);
        }
    }
}
