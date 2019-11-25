/*
 * Copyright 2019 Danny van Heumen
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

package org.simplify4u.plugins.skipfilters;

import org.apache.maven.artifact.Artifact;

import java.util.Arrays;
import java.util.Objects;

import static java.util.Arrays.asList;
import static java.util.Arrays.stream;
import static java.util.Objects.requireNonNull;

/**
 * A compositor for {@link SkipFilter}s.
 * <p>
 * The composite of provided <code>SkipFilter</code>s will only pass the test
 * if all individual <code>SkipFilter</code>s pass the test.
 */
public final class CompositeSkipper implements SkipFilter {

    private final Iterable<SkipFilter> filters;

    /**
     * Constructor to compose any number of {@link SkipFilter}s.
     *
     * @param filters the filters
     */
    public CompositeSkipper(Iterable<SkipFilter> filters) {
        this.filters = requireNonNull(filters);
    }

    /**
     * Constructor to compose any number of {@link SkipFilter}s.
     *
     * @param filters the filters
     */
    public CompositeSkipper(SkipFilter... filters) {
        if (stream(filters).anyMatch(Objects::isNull)) {
            throw new NullPointerException("filter cannot be null");
        }
        this.filters = asList(filters);
    }

    @Override
    public boolean shouldSkipArtifact(Artifact artifact) {
        requireNonNull(artifact);
        for (final SkipFilter filter : this.filters) {
            if (filter.shouldSkipArtifact(artifact)) {
                return true;
            }
        }
        return false;
    }
}
