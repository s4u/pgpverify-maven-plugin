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

package org.simplify4u.plugins.skipfilters;

import org.apache.maven.RepositoryUtils;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.manager.ArtifactHandlerManager;
import org.apache.maven.model.Dependency;

/**
 * An interface for a filter that determines whether or not a particular artifact should be
 * processed or skipped, based on the mojo configuration.
 */
public interface SkipFilter {

    /**
     * Indicates whether an artifact should be skipped, based on the configuration of this
     * filter.
     *
     * @param artifact The artifact being considered for verification.
     * @return {@code true} if the artifact should be skipped; {@code false} if it should be
     *         processed.
     */
    boolean shouldSkipArtifact(final Artifact artifact);

    /**
     * Indicates whether a dependency should be skipped, based on the configuration of this
     * filter.
     *
     * @param dependency The artifact being considered for verification.
     * @param artifactHandlerManager a artifactHandlerManager
     * @return {@code true} if the artifact should be skipped; {@code false} if it should be
     *         processed.
     */
    default boolean shouldSkipDependency(Dependency dependency, ArtifactHandlerManager artifactHandlerManager) {
        DefaultArtifact artifact =
                new DefaultArtifact(dependency.getGroupId(), dependency.getArtifactId(), dependency.getVersion(),
                        dependency.getScope(), dependency.getType(), dependency.getClassifier(),
                        artifactHandlerManager.getArtifactHandler(dependency.getType()));
        return shouldSkipArtifact(artifact);
    }

    default boolean shouldSkipDependency(org.eclipse.aether.graph.Dependency dependency) {

        Artifact artifact = RepositoryUtils.toArtifact(dependency.getArtifact());
        artifact.setScope(dependency.getScope());
        artifact.setOptional(dependency.getOptional());
        return shouldSkipArtifact(artifact);
    }
}
