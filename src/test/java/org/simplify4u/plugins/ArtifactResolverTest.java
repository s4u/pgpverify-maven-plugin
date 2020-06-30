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

package org.simplify4u.plugins;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.artifact.repository.ArtifactRepository;
import org.apache.maven.artifact.resolver.ArtifactResolutionRequest;
import org.apache.maven.artifact.resolver.ArtifactResolutionResult;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectBuildingRequest;
import org.apache.maven.repository.RepositorySystem;
import org.mockito.stubbing.Answer;
import org.simplify4u.plugins.ArtifactResolver.Configuration;
import org.simplify4u.plugins.ArtifactResolver.SignatureRequirement;
import org.simplify4u.plugins.skipfilters.CompositeSkipper;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptySet;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.times;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

public class ArtifactResolverTest {

    @Test
    public void testConstructArtifactResolverWithNull() {
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        final ArtifactRepository localRepository = mock(ArtifactRepository.class);
        assertThrows(NullPointerException.class,
                () -> new ArtifactResolver(null, null, null));
        assertThrows(NullPointerException.class,
                () -> new ArtifactResolver(null, localRepository, emptyList()));
        assertThrows(NullPointerException.class,
                () -> new ArtifactResolver(repositorySystem, null, emptyList()));
        assertThrows(NullPointerException.class,
                () -> new ArtifactResolver(repositorySystem, localRepository, null));
    }

    @Test
    public void testResolveProjectArtifactsEmpty() throws MojoExecutionException {
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        final MavenSession session = mock(MavenSession.class);
        final ProjectBuildingRequest projectBuildingRequest = mock(ProjectBuildingRequest.class);
        when(session.getProjectBuildingRequest()).thenReturn(projectBuildingRequest);
        final ArtifactRepository localRepository = mock(ArtifactRepository.class);
        when(projectBuildingRequest.getLocalRepository()).thenReturn(localRepository);
        final List<ArtifactRepository> remoteRepositories = emptyList();
        when(projectBuildingRequest.getRemoteRepositories()).thenReturn(remoteRepositories);

        final ArtifactResolver resolver = new ArtifactResolver(repositorySystem, localRepository, remoteRepositories);
        final MavenProject project = mock(MavenProject.class);

        final Configuration config = new Configuration(new CompositeSkipper(emptyList()),
                new CompositeSkipper(emptyList()), false, false, false, false);
        final Set<Artifact> resolved = resolver.resolveProjectArtifacts(project, config);
        assertEquals(emptySet(), resolved);
    }

    @Test
    public void testResolveProjectArtifactsWithoutPoms() throws MojoExecutionException {
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        final MavenSession session = mock(MavenSession.class);
        final ProjectBuildingRequest projectBuildingRequest = mock(ProjectBuildingRequest.class);
        when(session.getProjectBuildingRequest()).thenReturn(projectBuildingRequest);
        final ArtifactRepository localRepository = mock(ArtifactRepository.class);
        when(projectBuildingRequest.getLocalRepository()).thenReturn(localRepository);
        final List<ArtifactRepository> remoteRepositories = emptyList();
        when(projectBuildingRequest.getRemoteRepositories()).thenReturn(remoteRepositories);
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            final Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolvedVersion(artifact.getVersion());
            artifact.setResolved(true);
            return new ArtifactResolutionResult();
        });
        final ArtifactResolver resolver = new ArtifactResolver(repositorySystem, localRepository, remoteRepositories);
        final MavenProject project = mock(MavenProject.class);
        final DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", "classifier", null);
        when(project.getArtifacts()).thenReturn(singleton(artifact));

        final Configuration config = new Configuration(new CompositeSkipper(emptyList()),
                new CompositeSkipper(emptyList()), false, false, false, false);
        final Set<Artifact> resolved = resolver.resolveProjectArtifacts(project, config);
        assertEquals(1, resolved.size());
        assertTrue(resolved.iterator().next().isResolved());
    }

    @Test
    public void testResolveProjectArtifactsWithPoms() throws MojoExecutionException {
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        final MavenSession session = mock(MavenSession.class);
        final ProjectBuildingRequest projectBuildingRequest = mock(ProjectBuildingRequest.class);
        when(session.getProjectBuildingRequest()).thenReturn(projectBuildingRequest);
        final ArtifactRepository localRepository = mock(ArtifactRepository.class);
        when(projectBuildingRequest.getLocalRepository()).thenReturn(localRepository);
        final List<ArtifactRepository> remoteRepositories = emptyList();
        when(projectBuildingRequest.getRemoteRepositories()).thenReturn(remoteRepositories);
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            final Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolved(true);
            return new ArtifactResolutionResult();
        });
        when(repositorySystem.createProjectArtifact(eq("g"), eq("a"), eq("1.0")))
                .thenReturn(new DefaultArtifact("g", "a", "1.0", "compile", "pom", "classifier", null));
        final ArtifactResolver resolver = new ArtifactResolver(repositorySystem, localRepository, remoteRepositories);
        final MavenProject project = mock(MavenProject.class);
        final DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", "classifier", null);
        when(project.getArtifacts()).thenReturn(singleton(artifact));

        final Configuration config = new Configuration(new CompositeSkipper(emptyList()),
                new CompositeSkipper(emptyList()), true, false, false, false);
        final Set<Artifact> resolvedSet = resolver.resolveProjectArtifacts(project, config);
        verify(repositorySystem, times(1))
                .createProjectArtifact(eq("g"), eq("a"), eq("1.0"));
        assertEquals(resolvedSet.size(), 2);
        final Artifact[] resolved = resolvedSet.toArray(new Artifact[0]);
        assertTrue(resolved[0].isResolved());
        assertEquals(resolved[0].getType(), "jar");
        assertTrue(resolved[1].isResolved());
        assertEquals(resolved[1].getType(), "pom");
    }

    @Test
    public void testResolveSignaturesEmpty() throws MojoExecutionException {
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        final MavenSession session = mock(MavenSession.class);
        final ProjectBuildingRequest projectBuildingRequest = mock(ProjectBuildingRequest.class);
        when(session.getProjectBuildingRequest()).thenReturn(projectBuildingRequest);
        final ArtifactRepository localRepository = mock(ArtifactRepository.class);
        when(projectBuildingRequest.getLocalRepository()).thenReturn(localRepository);
        final List<ArtifactRepository> remoteRepositories = emptyList();
        when(projectBuildingRequest.getRemoteRepositories()).thenReturn(remoteRepositories);
        final ArtifactResolver resolver = new ArtifactResolver(repositorySystem, localRepository, remoteRepositories);
        final Map<Artifact, Artifact> resolvedSignatures = resolver.resolveSignatures(
                emptyList(), SignatureRequirement.NONE);
        assertEquals(resolvedSignatures.size(), 0);
    }

    @Test
    public void testResolveSignaturesResolved() throws MojoExecutionException {
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        final MavenSession session = mock(MavenSession.class);
        final ProjectBuildingRequest projectBuildingRequest = mock(ProjectBuildingRequest.class);
        when(session.getProjectBuildingRequest()).thenReturn(projectBuildingRequest);
        final ArtifactRepository localRepository = mock(ArtifactRepository.class);
        when(projectBuildingRequest.getLocalRepository()).thenReturn(localRepository);
        final List<ArtifactRepository> remoteRepositories = emptyList();
        when(projectBuildingRequest.getRemoteRepositories()).thenReturn(remoteRepositories);
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            final Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolved(true);
            return new ArtifactResolutionResult();
        });
        when(repositorySystem.createArtifactWithClassifier(eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull()))
                .thenReturn(new DefaultArtifact("g", "a", "1.0", "compile", "mock-signature-artifact", null, new DefaultArtifactHandler()));
        final ArtifactResolver resolver = new ArtifactResolver(repositorySystem, localRepository, remoteRepositories);
        final MavenProject project = mock(MavenProject.class);
        final DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", null, new DefaultArtifactHandler());
        when(project.getArtifacts()).thenReturn(singleton(artifact));

        final Map<Artifact, Artifact> resolvedSignatures = resolver.resolveSignatures(
                singleton(artifact), SignatureRequirement.NONE);
        verify(repositorySystem, times(1)).createArtifactWithClassifier(
                eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull());
        assertEquals(resolvedSignatures.size(), 1);
        final Map.Entry<Artifact, Artifact> entry = resolvedSignatures.entrySet().iterator().next();
        assertEquals(entry.getKey(), artifact);
        assertEquals(entry.getValue().getGroupId(), "g");
        assertEquals(entry.getValue().getArtifactId(), "a");
        assertEquals(entry.getValue().getVersion(), "1.0");
        assertNull(entry.getValue().getClassifier());
        assertEquals(entry.getValue().getType(), "mock-signature-artifact");
    }

    @Test
    public void testResolveSignaturesUnresolvedNone() throws MojoExecutionException {
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        final MavenSession session = mock(MavenSession.class);
        final ProjectBuildingRequest projectBuildingRequest = mock(ProjectBuildingRequest.class);
        when(session.getProjectBuildingRequest()).thenReturn(projectBuildingRequest);
        final ArtifactRepository localRepository = mock(ArtifactRepository.class);
        when(projectBuildingRequest.getLocalRepository()).thenReturn(localRepository);
        final List<ArtifactRepository> remoteRepositories = emptyList();
        when(projectBuildingRequest.getRemoteRepositories()).thenReturn(remoteRepositories);
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            final Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolved(false);
            final ArtifactResolutionResult result = new ArtifactResolutionResult();
            result.setUnresolvedArtifacts(singletonList(artifact));
            return result;
        });
        when(repositorySystem.createArtifactWithClassifier(eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull()))
                .thenReturn(new DefaultArtifact("g", "a", "1.0", "compile", "mock-signature-artifact", null, new DefaultArtifactHandler()));
        final ArtifactResolver resolver = new ArtifactResolver(repositorySystem, localRepository, remoteRepositories);
        final MavenProject project = mock(MavenProject.class);
        final DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", null, new DefaultArtifactHandler());
        when(project.getArtifacts()).thenReturn(singleton(artifact));

        final Map<Artifact, Artifact> resolvedSignatures = resolver.resolveSignatures(
                singleton(artifact), SignatureRequirement.NONE);
        verify(repositorySystem, times(1)).createArtifactWithClassifier(
                eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull());
        assertEquals(resolvedSignatures.size(), 0);
    }

    @Test
    public void testResolveSignaturesUnresolvedStrict() throws MojoExecutionException {
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        final MavenSession session = mock(MavenSession.class);
        final ProjectBuildingRequest projectBuildingRequest = mock(ProjectBuildingRequest.class);
        when(session.getProjectBuildingRequest()).thenReturn(projectBuildingRequest);
        final ArtifactRepository localRepository = mock(ArtifactRepository.class);
        when(projectBuildingRequest.getLocalRepository()).thenReturn(localRepository);
        final List<ArtifactRepository> remoteRepositories = emptyList();
        when(projectBuildingRequest.getRemoteRepositories()).thenReturn(remoteRepositories);
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            final Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolved(false);
            final ArtifactResolutionResult result = new ArtifactResolutionResult();
            result.setUnresolvedArtifacts(singletonList(artifact));
            return result;
        });
        when(repositorySystem.createArtifactWithClassifier(eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull()))
                .thenReturn(new DefaultArtifact("g", "a", "1.0", "compile", "mock-signature-artifact", null, new DefaultArtifactHandler()));
        final ArtifactResolver resolver = new ArtifactResolver(repositorySystem, localRepository, remoteRepositories);
        final MavenProject project = mock(MavenProject.class);
        final DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", null, new DefaultArtifactHandler());
        when(project.getArtifacts()).thenReturn(singleton(artifact));

        final Map<Artifact, Artifact> resolvedSignatures = resolver.resolveSignatures(
                singleton(artifact), SignatureRequirement.STRICT);
        verify(repositorySystem, times(1)).createArtifactWithClassifier(
                eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull());
        assertEquals(resolvedSignatures.size(), 1);
        final Map.Entry<Artifact, Artifact> entry = resolvedSignatures.entrySet().iterator().next();
        assertEquals(entry.getKey(), artifact);
        assertNull(entry.getValue());
    }

    @Test
    public void testResolveSignaturesUnresolvedRequired() {
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        final MavenSession session = mock(MavenSession.class);
        final ProjectBuildingRequest projectBuildingRequest = mock(ProjectBuildingRequest.class);
        when(session.getProjectBuildingRequest()).thenReturn(projectBuildingRequest);
        final ArtifactRepository localRepository = mock(ArtifactRepository.class);
        when(projectBuildingRequest.getLocalRepository()).thenReturn(localRepository);
        final List<ArtifactRepository> remoteRepositories = emptyList();
        when(projectBuildingRequest.getRemoteRepositories()).thenReturn(remoteRepositories);
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            final Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolved(false);
            final ArtifactResolutionResult result = new ArtifactResolutionResult();
            result.setUnresolvedArtifacts(singletonList(artifact));
            return result;
        });
        when(repositorySystem.createArtifactWithClassifier(eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull()))
                .thenReturn(new DefaultArtifact("g", "a", "1.0", "compile", "mock-signature-artifact", null, new DefaultArtifactHandler()));
        final ArtifactResolver resolver = new ArtifactResolver(repositorySystem, localRepository, remoteRepositories);
        final MavenProject project = mock(MavenProject.class);
        final DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", null, new DefaultArtifactHandler());
        when(project.getArtifacts()).thenReturn(singleton(artifact));

        assertThrows(MojoExecutionException.class, () -> resolver.resolveSignatures(singleton(artifact), SignatureRequirement.REQUIRED));
    }

    @Test(dataProvider = "verify-plugin-dependencies-combos")
    public void testEnablingValidatingPluginDependenciesEnablesPlugins(boolean verifyPlugins,
                boolean verifyPluginDependencies, boolean pluginsEnabled, boolean pluginDependenciesEnabled) {
        final Configuration config = new Configuration(new CompositeSkipper(), new CompositeSkipper(),
                false, verifyPlugins, verifyPluginDependencies, false);
        assertThat(config.verifyPluginDependencies).isEqualTo(pluginDependenciesEnabled);
        assertThat(config.verifyPlugins).isEqualTo(pluginsEnabled);
    }

    @DataProvider(name = "verify-plugin-dependencies-combos")
    public Object[][] providerVerifyPluginDependenciesCombos() {
        return new Object[][]{
                {false, false, false, false},
                {false, true, true, true},
                {true, false, true, false},
                {true, true, true, true},
        };
    }
}