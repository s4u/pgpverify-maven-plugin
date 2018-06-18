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
 * A failure strategy that does not allow retrying any failed requests.
 */
public class NoRetryStrategy implements RequestFailureStrategy {
    @Override
    public boolean canRetry(final URL url, final URLConnection connection,
                            final IOException cause) {
        return false;
    }

    @Override
    public void onRetry(final URL url, final IOException cause) {
        // No-op -- will never be invoked.
    }
}
