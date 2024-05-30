/*
 * Copyright 2019 Danny van Heumen
 * Copyright 2021 Slawomir Jaranowski
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

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.maven.RepositoryUtils;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.artifact.handler.manager.ArtifactHandlerManager;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.assertj.core.api.Condition;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.ArtifactResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;
import org.simplify4u.plugins.ArtifactResolver.Configuration;
import org.simplify4u.plugins.skipfilters.CompositeSkipper;

import static java.util.Collections.emptyList;
import static java.util.Collections.singleton;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ArtifactResolverTest {

    private static final Condition<Artifact> IS_JAR_TYPE = new Condition<>(a -> "jar".equals(a.getType()), "is jar type");
    private static final Condition<Artifact> IS_POM_TYPE = new Condition<>(a -> "pom".equals(a.getType()), "is pom type");

    @Mock
    private org.eclipse.aether.RepositorySystem aetherRepositorySystem;

    @Mock
    private RepositorySystemSession repositorySession;

    @Mock
    private ArtifactHandlerManager artifactHandlerManager;

    @Mock
    private MavenSession session;

    @Mock
    private MavenProject project;

    private ArtifactResolver resolver;

    @BeforeEach
    void setup() {
        when(session.getCurrentProject()).thenReturn(project);
        when(session.getRepositorySession()).thenReturn(repositorySession);
        resolver = new ArtifactResolver(session, aetherRepositorySystem, artifactHandlerManager);
    }

    @Test
    void testConstructArtifactResolverWithNull() {

        reset(session, project);

        assertThatCode(() -> new ArtifactResolver(null, null, null))
                .isExactlyInstanceOf(NullPointerException.class);

        assertThatCode(() -> new ArtifactResolver(session, null, null))
                .isExactlyInstanceOf(NullPointerException.class);

        assertThatCode(() -> new ArtifactResolver(session, null, null))
                .isExactlyInstanceOf(NullPointerException.class);

        doThrow(new NullPointerException()).when(session).getCurrentProject();
        assertThatCode(() -> new ArtifactResolver(session, null, null))
                .isExactlyInstanceOf(NullPointerException.class);
    }

    @Test
    void testResolveProjectArtifactsEmpty() {

        // given
        Configuration config = new Configuration(new CompositeSkipper(emptyList()),
                new CompositeSkipper(emptyList()), false, false, false, false);

        // when
        Set<Artifact> resolved = resolver.resolveProjectArtifacts(project, config);

        // then
        assertThat(resolved).isEmpty();
    }

    @Test
    void testResolveProjectArtifactsWithoutPoms() throws Exception {

        // given
        DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", "classifier", new DefaultArtifactHandler("jar"));

        when(aetherRepositorySystem.resolveArtifacts(any(), any())).thenAnswer((Answer<List<ArtifactResult>>) invocation -> {
            Collection<ArtifactRequest> artifactsRequests = invocation.getArgument(1);
            assertThat(artifactsRequests).hasSize(1);
            ArtifactRequest artifactRequest = artifactsRequests.iterator().next();
            ArtifactResult artifactResult = new ArtifactResult(artifactRequest);
            org.eclipse.aether.artifact.Artifact resolvedArtifact = artifactRequest.getArtifact();
            resolvedArtifact = resolvedArtifact.setFile(new File("."));
            artifactResult.setArtifact(resolvedArtifact);
            return Collections.singletonList(artifactResult);
        });


        when(project.getArtifacts()).thenReturn(singleton(artifact));

        Configuration config = new Configuration(new CompositeSkipper(emptyList()),
                new CompositeSkipper(emptyList()), false, false, false, false);

        // when
        Set<Artifact> resolved = resolver.resolveProjectArtifacts(project, config);

        // then
        assertThat(resolved)
                .hasSize(1)
                .allMatch(Artifact::isResolved);
    }

    @Test
    void testResolveProjectArtifactsWithPoms() throws Exception {

        // given
        DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", "classifier", new DefaultArtifactHandler("jar"));
        when(aetherRepositorySystem.resolveArtifacts(any(), any())).thenAnswer((Answer<List<ArtifactResult>>) invocation -> {
            Collection<ArtifactRequest> artifactsRequests = invocation.getArgument(1);
            assertThat(artifactsRequests).hasSize(2);

            Iterator<ArtifactRequest> iterator = artifactsRequests.iterator();
            List<ArtifactResult> results = new ArrayList<>();
            ArtifactRequest artifactRequest = iterator.next();
            ArtifactResult artifactResult = new ArtifactResult(artifactRequest);
            org.eclipse.aether.artifact.Artifact resolvedArtifact = artifactRequest.getArtifact();
            resolvedArtifact = resolvedArtifact.setFile(new File("."));
            artifactResult.setArtifact(resolvedArtifact);
            results.add(artifactResult);

            artifactRequest = iterator.next();
            artifactResult = new ArtifactResult(artifactRequest);
            resolvedArtifact = artifactRequest.getArtifact();
            resolvedArtifact = resolvedArtifact.setFile(new File("."));
            artifactResult.setArtifact(resolvedArtifact);
            results.add(artifactResult);

            return results;
        });

        when(project.getArtifacts()).thenReturn(singleton(artifact));

        Configuration config = new Configuration(new CompositeSkipper(emptyList()),
                new CompositeSkipper(emptyList()), true, false, false, false);

        // when
        Set<Artifact> resolved = resolver.resolveProjectArtifacts(project, config);

        // then

        assertThat(resolved).hasSize(2)
                .allMatch(Artifact::isResolved)
                .areExactly(1, IS_JAR_TYPE)
                .areExactly(1, IS_POM_TYPE);
    }

    @Test
    void testResolveSignaturesEmpty() {

        // when
        Map<Artifact, Artifact> resolved = resolver.resolveSignatures(emptyList());

        // then
        assertThat(resolved).isEmpty();
    }

    @Test
    void testResolveSignaturesResolved() throws ArtifactResolutionException {

        // given
        DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", null, new DefaultArtifactHandler());

        when(aetherRepositorySystem.resolveArtifacts(any(), any())).thenAnswer((Answer<List<ArtifactResult>>) invocation -> {
            Collection<ArtifactRequest> artifactsRequests = invocation.getArgument(1);
            assertThat(artifactsRequests).hasSize(1);
            ArtifactRequest artifactRequest = artifactsRequests.iterator().next();
            ArtifactResult artifactResult = new ArtifactResult(artifactRequest);
            org.eclipse.aether.artifact.Artifact resolvedArtifact = RepositoryUtils.toArtifact(artifact);
            resolvedArtifact = resolvedArtifact.setFile(new File("."));
            artifactResult.setArtifact(resolvedArtifact);
            return Collections.singletonList(artifactResult);
        });

        // then
        Map<Artifact, Artifact> resolved = resolver.resolveSignatures(singleton(artifact));

        // then
        verify(aetherRepositorySystem).resolveArtifacts(any(), any());

        assertThat(resolved)
                .hasSize(1)
                .containsOnlyKeys(artifact);

        Artifact value = resolved.entrySet().iterator().next().getValue();
        assertThat(value.getGroupId()).isEqualTo("g");
        assertThat(value.getArtifactId()).isEqualTo("a");
        assertThat(value.getVersion()).isEqualTo("1.0");
        assertThat(value.getClassifier()).isNull();
        assertThat(value.getType()).isEqualTo("jar");
        assertThat(value.isResolved()).isTrue();
    }

    @Test
    void testResolveSignaturesUnresolvedNone() throws ArtifactResolutionException {
        // given
        DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", null, new DefaultArtifactHandler());

        when(aetherRepositorySystem.resolveArtifacts(any(), any())).thenAnswer((Answer<List<ArtifactResult>>) invocation -> {
            Collection<ArtifactRequest> artifactsRequests = invocation.getArgument(1);
            assertThat(artifactsRequests).hasSize(1);
            ArtifactRequest artifactRequest = artifactsRequests.iterator().next();
            ArtifactResult artifactResult = new ArtifactResult(artifactRequest);
            org.eclipse.aether.artifact.Artifact resolvedArtifact = RepositoryUtils.toArtifact(artifact);
            artifactResult.setArtifact(resolvedArtifact);
            throw new ArtifactResolutionException(Collections.singletonList(artifactResult));
        });


        // when
        Map<Artifact, Artifact> resolved = resolver.resolveSignatures(singleton(artifact));

        // then
        verify(aetherRepositorySystem).resolveArtifacts(any(), any());

        assertThat(resolved)
                .hasSize(1)
                .containsOnlyKeys(artifact);

        Artifact value = resolved.entrySet().iterator().next().getValue();
        assertThat(value.getGroupId()).isEqualTo("g");
        assertThat(value.getArtifactId()).isEqualTo("a");
        assertThat(value.getVersion()).isEqualTo("1.0");
        assertThat(value.getClassifier()).isNull();
        assertThat(value.getType()).isEqualTo("jar");
        assertThat(value.isResolved()).isFalse();
    }

    @ParameterizedTest
    @MethodSource("providerVerifyPluginDependenciesCombos")
    void testEnablingValidatingPluginDependenciesEnablesPlugins(boolean verifyPlugins,
            boolean verifyPluginDependencies, boolean pluginsEnabled, boolean pluginDependenciesEnabled) {

        Configuration config = new Configuration(new CompositeSkipper(), new CompositeSkipper(),
                false, verifyPlugins, verifyPluginDependencies, false);

        assertThat(config.verifyPluginDependencies).isEqualTo(pluginDependenciesEnabled);
        assertThat(config.verifyPlugins).isEqualTo(pluginsEnabled);
    }

    public static Object[][] providerVerifyPluginDependenciesCombos() {
        return new Object[][]{
                {false, false, false, false},
                {false, true, true, true},
                {true, false, true, false},
                {true, true, true, true},
        };
    }
}
