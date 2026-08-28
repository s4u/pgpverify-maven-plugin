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
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.execution.ProjectDependencyGraph;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ReactorDependencySkipperTest {

    @Mock
    private MavenSession session;

    @Mock
    private ProjectDependencyGraph graph;

    @Mock
    private MavenProject currentProject;

    @Mock
    private MavenProject upstreamProject;

    private static Artifact artifact(String group, String artifactId, String version) {
        return new DefaultArtifact(group, artifactId, version, "compile", "jar", "", null);
    }

    @Test
    void nullProjectDependencyGraphDoesNotThrow() {
        when(session.getProjectDependencyGraph()).thenReturn(null);

        final ReactorDependencySkipper filter = new ReactorDependencySkipper(session);

        assertFalse(filter.shouldSkipArtifact(artifact("abc", "def", "1.0.0")));
    }

    @Test
    void nullUpstreamProjectsDoesNotThrow() {
        when(session.getProjectDependencyGraph()).thenReturn(graph);
        when(session.getCurrentProject()).thenReturn(currentProject);
        when(graph.getUpstreamProjects(currentProject, true)).thenReturn(null);

        final ReactorDependencySkipper filter = new ReactorDependencySkipper(session);

        assertFalse(filter.shouldSkipArtifact(artifact("abc", "def", "1.0.0")));
    }

    @Test
    void skipsMatchingUpstreamReactorArtifact() {
        when(session.getProjectDependencyGraph()).thenReturn(graph);
        when(session.getCurrentProject()).thenReturn(currentProject);
        when(graph.getUpstreamProjects(currentProject, true)).thenReturn(singletonList(upstreamProject));
        when(upstreamProject.getArtifact()).thenReturn(artifact("g", "a", "1.0"));

        final ReactorDependencySkipper filter = new ReactorDependencySkipper(session);

        assertTrue(filter.shouldSkipArtifact(artifact("g", "a", "1.0")));
        assertFalse(filter.shouldSkipArtifact(artifact("other", "a", "1.0")));
    }
}
