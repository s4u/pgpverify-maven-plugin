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

import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

import java.util.List;

/**
 * A filter that always skips verification of upstream dependencies that are being built as part of
 * the current build reactor.
 */
public class ReactorDependencySkipper implements SkipFilter {
    private final List<MavenProject> upstreamProjects;

    /**
     * Constructor for {@code ReactorDependencySkipper}.
     *
     * @param currentProject
     *   The project currently being built.
     * @param session
     *   The current maven session.
     */
    public ReactorDependencySkipper(final MavenProject currentProject,
                                    final MavenSession session) {
        this.upstreamProjects =
            session.getProjectDependencyGraph().getUpstreamProjects(currentProject, true);
    }

    @Override
    public boolean shouldSkipArtifact(Artifact artifact) {
        return this.isUpstreamReactorDependency(artifact);
    }

    /**
     * Check whether or not the specified artifact is an upstream dependency of this project in the
     * current Maven build.
     *
     * @param   artifact
     *          The to check against upstream reactor dependencies.
     *
     * @return  {@code true} if the specified artifact is in the current Maven reactor build and is
     *          a direct or transitive dependency of the current project; {@code false} if it is
     *          not either.
     */
    private boolean isUpstreamReactorDependency(final Artifact artifact) {
        for (final MavenProject upstreamProject : this.upstreamProjects) {
            if (this.artifactMatchesProject(artifact, upstreamProject)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check whether the specified artifact belongs to the specified Maven project.
     *
     * @param artifact
     *   The artifact being checked.
     * @param project
     *   The project to which the artifact will be compared.
     *
     * @return
     *   {@code true} if the artifact was produced by the specified project; or
     *   {@code false} if it is not.
     */
    private boolean artifactMatchesProject(final Artifact artifact,
                                           final MavenProject project) {
        final Artifact projectArtifact = project.getArtifact();

        return projectArtifact != null
               && this.artifactsMatch(projectArtifact, artifact);
    }

    /**
     * Check whether the specified artifacts are equivalent, or at least
     * identify the same group, artifact ID, and version.
     *
     * @param artifact1
     *   The first artifact.
     * @param artifact2
     *   The second artifact.
     *
     * @return
     *   If either the two artifacts are equal or correspond to the same Maven
     *   coordinates.
     */
    private boolean artifactsMatch(final Artifact artifact1,
                                   final Artifact artifact2) {
        return artifact1.equals(artifact2)
            || (artifact1.getGroupId().equals(artifact2.getGroupId())
                && artifact1.getArtifactId().equals(artifact2.getArtifactId())
                && artifact1.getVersion().equals(artifact2.getVersion()));
    }
}
