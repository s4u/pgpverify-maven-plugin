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
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.apache.maven.repository.RepositorySystem;
import org.mockito.stubbing.Answer;
import org.simplify4u.plugins.ArtifactResolver.SignatureRequirement;
import org.simplify4u.plugins.skipfilters.CompositeSkipper;
import org.testng.annotations.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptySet;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
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
        final Log log = mock(Log.class);
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        final ArtifactRepository localRepository = mock(ArtifactRepository.class);
        final List<ArtifactRepository> remoteRepositories = emptyList();
        assertThrows(NullPointerException.class,
                () -> new ArtifactResolver(null, null, null, null));
        assertThrows(NullPointerException.class,
                () -> new ArtifactResolver(null, repositorySystem, localRepository, remoteRepositories));
        assertThrows(NullPointerException.class,
                () -> new ArtifactResolver(log, null, localRepository, remoteRepositories));
        assertThrows(NullPointerException.class,
                () -> new ArtifactResolver(log, repositorySystem, null, remoteRepositories));
        assertThrows(NullPointerException.class,
                () -> new ArtifactResolver(log, repositorySystem, localRepository, null));
    }

    @Test
    public void testResolveProjectArtifactsEmpty() throws MojoExecutionException {
        final Log log = mock(Log.class);
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        final ArtifactResolver resolver = new ArtifactResolver(log, repositorySystem, mock(ArtifactRepository.class), emptyList());
        final MavenProject project = mock(MavenProject.class);

        final Set<Artifact> resolved = resolver.resolveProjectArtifacts(project,
                new CompositeSkipper(emptyList()), false);
        assertEquals(emptySet(), resolved);
    }

    @Test
    public void testResolveProjectArtifactsWithoutPoms() throws MojoExecutionException {
        final Log log = mock(Log.class);
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            final Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolvedVersion(artifact.getVersion());
            artifact.setResolved(true);
            return new ArtifactResolutionResult();
        });
        final ArtifactResolver resolver = new ArtifactResolver(log, repositorySystem, mock(ArtifactRepository.class), emptyList());
        final MavenProject project = mock(MavenProject.class);
        final DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", "classifier", null);
        when(project.getArtifacts()).thenReturn(singleton(artifact));

        final Set<Artifact> resolved = resolver.resolveProjectArtifacts(project,
                new CompositeSkipper(emptyList()), false);
        assertEquals(1, resolved.size());
        assertTrue(resolved.iterator().next().isResolved());
    }

    @Test
    public void testResolveProjectArtifactsWithPoms() throws MojoExecutionException {
        final Log log = mock(Log.class);
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            final Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolved(true);
            return new ArtifactResolutionResult();
        });
        when(repositorySystem.createProjectArtifact(eq("g"), eq("a"), eq("1.0")))
                .thenReturn(new DefaultArtifact("g", "a", "1.0", "compile", "pom", "classifier", null));
        final ArtifactResolver resolver = new ArtifactResolver(log, repositorySystem, mock(ArtifactRepository.class), emptyList());
        final MavenProject project = mock(MavenProject.class);
        final DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", "classifier", null);
        when(project.getArtifacts()).thenReturn(singleton(artifact));

        final Set<Artifact> resolvedSet = resolver.resolveProjectArtifacts(project,
                new CompositeSkipper(emptyList()), true);
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
        final Log log = mock(Log.class);
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        final ArtifactResolver resolver = new ArtifactResolver(log, repositorySystem, mock(ArtifactRepository.class), emptyList());
        final Map<Artifact, Artifact> resolvedSignatures = resolver.resolveSignatures(
                emptyList(), SignatureRequirement.NONE);
        assertEquals(resolvedSignatures.size(), 0);
    }

    @Test
    public void testResolveSignaturesResolved() throws MojoExecutionException {
        final Log log = mock(Log.class);
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            final Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolved(true);
            return new ArtifactResolutionResult();
        });
        when(repositorySystem.createArtifactWithClassifier(eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull()))
                .thenReturn(new DefaultArtifact("g", "a", "1.0", "compile", "mock-signature-artifact", null, new DefaultArtifactHandler()));
        final ArtifactResolver resolver = new ArtifactResolver(log, repositorySystem, mock(ArtifactRepository.class), emptyList());
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
        final Log log = mock(Log.class);
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            final Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolved(false);
            final ArtifactResolutionResult result = new ArtifactResolutionResult();
            result.setUnresolvedArtifacts(singletonList(artifact));
            return result;
        });
        when(repositorySystem.createArtifactWithClassifier(eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull()))
                .thenReturn(new DefaultArtifact("g", "a", "1.0", "compile", "mock-signature-artifact", null, new DefaultArtifactHandler()));
        final ArtifactResolver resolver = new ArtifactResolver(log, repositorySystem, mock(ArtifactRepository.class), emptyList());
        final MavenProject project = mock(MavenProject.class);
        final DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", null, new DefaultArtifactHandler());
        when(project.getArtifacts()).thenReturn(singleton(artifact));

        final Map<Artifact, Artifact> resolvedSignatures = resolver.resolveSignatures(
                singleton(artifact), SignatureRequirement.NONE);
        verify(repositorySystem, times(1)).createArtifactWithClassifier(
                eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull());
        verify(log).warn(eq("No signature for g:a:jar:1.0"));
        assertEquals(resolvedSignatures.size(), 0);
    }

    @Test
    public void testResolveSignaturesUnresolvedStrict() throws MojoExecutionException {
        final Log log = mock(Log.class);
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            final Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolved(false);
            final ArtifactResolutionResult result = new ArtifactResolutionResult();
            result.setUnresolvedArtifacts(singletonList(artifact));
            return result;
        });
        when(repositorySystem.createArtifactWithClassifier(eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull()))
                .thenReturn(new DefaultArtifact("g", "a", "1.0", "compile", "mock-signature-artifact", null, new DefaultArtifactHandler()));
        final ArtifactResolver resolver = new ArtifactResolver(log, repositorySystem, mock(ArtifactRepository.class), emptyList());
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
        final Log log = mock(Log.class);
        final RepositorySystem repositorySystem = mock(RepositorySystem.class);
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            final Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolved(false);
            final ArtifactResolutionResult result = new ArtifactResolutionResult();
            result.setUnresolvedArtifacts(singletonList(artifact));
            return result;
        });
        when(repositorySystem.createArtifactWithClassifier(eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull()))
                .thenReturn(new DefaultArtifact("g", "a", "1.0", "compile", "mock-signature-artifact", null, new DefaultArtifactHandler()));
        final ArtifactResolver resolver = new ArtifactResolver(log, repositorySystem, mock(ArtifactRepository.class), emptyList());
        final MavenProject project = mock(MavenProject.class);
        final DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", null, new DefaultArtifactHandler());
        when(project.getArtifacts()).thenReturn(singleton(artifact));

        assertThrows(MojoExecutionException.class, () -> resolver.resolveSignatures(singleton(artifact), SignatureRequirement.REQUIRED));
    }
}