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
import java.net.URLConnection;

/**
 * A failure strategy that automatically retries a request up to N times..
 *
 * <p>By default, this strategy will allow retrying up to ten times before
 * giving up. The maximum number of retries can be controlled by using the
 * {@link #RetryNTimesStrategy(int)} constructor.
 *
 * <p>As expected, instances of this strategy maintain a retry counter. For this
 * reason, after a request has been completed, the same failure strategy
 * instance should not be used for a subsequent request. A new failure strategy
 * instance should be created for each new request (excluding retries of the
 * same request).
 */
public class RetryNTimesStrategy implements RequestFailureStrategy {
    public static final int DEFAULT_MAX_RETRY_COUNT = 10;

    private final int maxRetryCount;

    private int currentRetryCount;

    /**
     * Constructor for {@code RetryNTimesStrategy}.
     *
     * <p>Creates a retry strategy that will allow retrying the same request up
     * to ten times.
     */
    public RetryNTimesStrategy() {
        this(DEFAULT_MAX_RETRY_COUNT);
    }

    /**
     * Constructor for {@code RetryNTimesStrategy}.
     *
     * <p>Creates a retry strategy that will allow retrying the same request up
     * to the specified number of times.
     *
     * @param maxRetryCount
     *   The maximum number of times that the request can be retried.
     */
    public RetryNTimesStrategy(final int maxRetryCount) {
        this.maxRetryCount      = maxRetryCount;
        this.currentRetryCount  = 0;
    }

    /**
     * Gets the maximum number of retries that this instance will attempt.
     *
     * @return  The maximum number of retries to attempt.
     */
    public int getMaxRetryCount() {
        return maxRetryCount;
    }

    /**
     * Gets the number of retries attempted so far for this instance.
     *
     * @return  The number of retries that have been attempted.
     */
    public int getCurrentRetryCount() {
        return this.currentRetryCount;
    }

    @Override
    public boolean canRetry(final URL url, final URLConnection connection,
                            final IOException cause) {
        return this.currentRetryCount < this.maxRetryCount;
    }

    @Override
    public void onRetry(URL url, IOException cause) {
        ++this.currentRetryCount;
    }
}
