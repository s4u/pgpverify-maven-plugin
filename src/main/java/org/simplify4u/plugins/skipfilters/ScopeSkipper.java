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
import org.apache.maven.artifact.resolver.filter.CumulativeScopeArtifactFilter;

import static java.util.Collections.singleton;
import static java.util.Objects.requireNonNull;

/**
 * Cumulative scope filter.
 */
public class ScopeSkipper implements SkipFilter {

    private final CumulativeScopeArtifactFilter filter;

    /**
     * Construction of cumulative scope filter.
     *
     * @param scope the maximum scope, meaning that if, e.g. 'test' scope is specified, then every scope
     *              chronologically prior to 'test' will also be included.
     */
    public ScopeSkipper(final String scope) {
        filter = new CumulativeScopeArtifactFilter(singleton(requireNonNull(scope)));
    }

    @Override
    public boolean shouldSkipArtifact(final Artifact artifact) {
        return !filter.include(artifact);
    }
}
