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
 * An interface for controlling how failures during HTTP requests are handled.
 *
 * <p>Most instances of this interface maintain a retry counter. For this
 * reason, after a request has been completed, the same failure strategy
 * instance should not be used for a subsequent requests. A new failure strategy
 * instance should be created for each new request (excluding retries of the
 * same request).
 */
public interface RequestFailureStrategy {
    /**
     * Indicate whether or not this strategy is willing to allow the request to
     * be retried.
     *
     * @param url
     *   The URL that was being requested.
     * @param connection
     *   The connection that failed.
     * @param cause
     *   The exception that was returned when the connection failed.
     *
     * @return  Whether or not a request to the specified URL can be retried if
     *          the cause of the failure was the specified exception.
     */
    boolean canRetry(final URL url, final URLConnection connection,
                     final IOException cause);

    /**
     * Notifies the strategy that a request to the specified URL is being
     * attempted after the specified exception caused the last attempt to fail.
     *
     * @param url
     *   The URL that is being retried.
     * @param cause
     *   The exception that was returned when the previous connection failed.
     */
    void onRetry(final URL url, final IOException cause);
}
