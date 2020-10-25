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

import java.util.Map;
import java.util.Set;

import static java.util.Collections.emptyList;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.times;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.artifact.repository.ArtifactRepository;
import org.apache.maven.artifact.resolver.ArtifactResolutionRequest;
import org.apache.maven.artifact.resolver.ArtifactResolutionResult;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.repository.RepositorySystem;
import org.assertj.core.api.Condition;
import org.mockito.Mock;
import org.mockito.stubbing.Answer;
import org.mockito.testng.MockitoTestNGListener;
import org.simplify4u.plugins.ArtifactResolver.Configuration;
import org.simplify4u.plugins.ArtifactResolver.SignatureRequirement;
import org.simplify4u.plugins.skipfilters.CompositeSkipper;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

@Listeners(MockitoTestNGListener.class)
public class ArtifactResolverTest {

    private static final Condition<Artifact> IS_JAR_TYPE = new Condition<>(a -> "jar".equals(a.getType()), "is jar type");
    private static final Condition<Artifact> IS_POM_TYPE = new Condition<>(a -> "pom".equals(a.getType()), "is pom type");

    @Mock
    private RepositorySystem repositorySystem;

    @Mock
    private ArtifactRepository localRepository;

    @Mock
    private MavenSession session;

    @Mock
    private MavenProject project;

    private ArtifactResolver resolver;

    @BeforeMethod
    void setup() {
        when(session.getLocalRepository()).thenReturn(localRepository);
        when(session.getCurrentProject()).thenReturn(project);
        when(project.getRemoteArtifactRepositories()).thenReturn(emptyList());

        resolver = new ArtifactResolver(repositorySystem, session);
    }

    @Test
    public void testConstructArtifactResolverWithNull() {

        reset(session, project);

        assertThatCode(() -> new ArtifactResolver(null, null))
                .isExactlyInstanceOf(NullPointerException.class);

        assertThatCode(() -> new ArtifactResolver(null, session))
                .isExactlyInstanceOf(NullPointerException.class);

        doThrow(new NullPointerException()).when(session).getLocalRepository();
        assertThatCode(() -> new ArtifactResolver(repositorySystem, session))
                .isExactlyInstanceOf(NullPointerException.class);

        doReturn(localRepository).when(session).getLocalRepository();
        doThrow(new NullPointerException()).when(session).getCurrentProject();
        assertThatCode(() -> new ArtifactResolver(repositorySystem, session))
                .isExactlyInstanceOf(NullPointerException.class);
    }

    @Test
    public void testResolveProjectArtifactsEmpty() throws MojoExecutionException {

        // given
        Configuration config = new Configuration(new CompositeSkipper(emptyList()),
                new CompositeSkipper(emptyList()), false, false, false, false);

        // when
        Set<Artifact> resolved = resolver.resolveProjectArtifacts(project, config);

        // then
        assertThat(resolved).isEmpty();
    }

    @Test
    public void testResolveProjectArtifactsWithoutPoms() throws MojoExecutionException {

        // given
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolvedVersion(artifact.getVersion());
            artifact.setResolved(true);
            return new ArtifactResolutionResult();
        });

        DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", "classifier", null);
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
    public void testResolveProjectArtifactsWithPoms() throws MojoExecutionException {

        // given
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolved(true);
            return new ArtifactResolutionResult();
        });

        when(repositorySystem.createProjectArtifact(eq("g"), eq("a"), eq("1.0")))
                .thenReturn(new DefaultArtifact("g", "a", "1.0", "compile", "pom", "classifier", null));

        DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", "classifier", null);
        when(project.getArtifacts()).thenReturn(singleton(artifact));

        Configuration config = new Configuration(new CompositeSkipper(emptyList()),
                new CompositeSkipper(emptyList()), true, false, false, false);

        // when
        Set<Artifact> resolved = resolver.resolveProjectArtifacts(project, config);

        // then
        verify(repositorySystem, times(1))
                .createProjectArtifact(eq("g"), eq("a"), eq("1.0"));

        assertThat(resolved).hasSize(2)
            .allMatch(Artifact::isResolved)
            .areExactly(1, IS_JAR_TYPE)
            .areExactly(1, IS_POM_TYPE);
    }

    @Test
    public void testResolveSignaturesEmpty() throws MojoExecutionException {

        // when
        Map<Artifact, Artifact> resolved = resolver.resolveSignatures(emptyList(), SignatureRequirement.NONE);

        // then
        assertThat(resolved).isEmpty();
    }

    @Test
    public void testResolveSignaturesResolved() throws MojoExecutionException {

        // given
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolved(true);
            return new ArtifactResolutionResult();
        });

        when(repositorySystem.createArtifactWithClassifier(eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull()))
                .thenReturn(new DefaultArtifact("g", "a", "1.0", "compile", "mock-signature-artifact", null, new DefaultArtifactHandler()));

        DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", null, new DefaultArtifactHandler());

        // then
        Map<Artifact, Artifact> resolved = resolver.resolveSignatures(singleton(artifact), SignatureRequirement.NONE);

        // then
        verify(repositorySystem, times(1)).createArtifactWithClassifier(
                eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull());

        assertThat(resolved)
                .hasSize(1)
                .containsOnlyKeys(artifact);

        Artifact value = resolved.entrySet().iterator().next().getValue();
        assertThat(value.getGroupId()).isEqualTo("g");
        assertThat(value.getArtifactId()).isEqualTo("a");
        assertThat(value.getVersion()).isEqualTo("1.0");
        assertThat(value.getClassifier()).isNull();
        assertThat(value.getType()).isEqualTo("mock-signature-artifact");
    }

    @Test
    public void testResolveSignaturesUnresolvedNone() throws MojoExecutionException {
        // given
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolved(false);
            ArtifactResolutionResult result = new ArtifactResolutionResult();
            result.setUnresolvedArtifacts(singletonList(artifact));
            return result;
        });

        when(repositorySystem.createArtifactWithClassifier(eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull()))
                .thenReturn(new DefaultArtifact("g", "a", "1.0", "compile", "mock-signature-artifact", null, new DefaultArtifactHandler()));

        DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", null, new DefaultArtifactHandler());

        // when
        Map<Artifact, Artifact> resolved = resolver.resolveSignatures(singleton(artifact), SignatureRequirement.NONE);

        // then
        verify(repositorySystem, times(1)).createArtifactWithClassifier(
                eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull());
        assertThat(resolved).hasSize(1);
    }

    @Test
    public void testResolveSignaturesUnresolvedRequired() {

        // given
        when(repositorySystem.resolve(isA(ArtifactResolutionRequest.class))).thenAnswer((Answer<ArtifactResolutionResult>) invocation -> {
            Artifact artifact = invocation.<ArtifactResolutionRequest>getArgument(0).getArtifact();
            artifact.setResolved(false);
            ArtifactResolutionResult result = new ArtifactResolutionResult();
            result.setUnresolvedArtifacts(singletonList(artifact));
            return result;
        });

        when(repositorySystem.createArtifactWithClassifier(eq("g"), eq("a"), eq("1.0"), eq("jar"), isNull()))
                .thenReturn(new DefaultArtifact("g", "a", "1.0", "compile", "mock-signature-artifact", null, new DefaultArtifactHandler()));

        DefaultArtifact artifact = new DefaultArtifact("g", "a", "1.0", "compile", "jar", null, new DefaultArtifactHandler());

        // when -> then
        assertThatCode(() -> resolver.resolveSignatures(singleton(artifact), SignatureRequirement.REQUIRED))
                .isExactlyInstanceOf(MojoExecutionException.class);
    }

    @Test(dataProvider = "verify-plugin-dependencies-combos")
    public void testEnablingValidatingPluginDependenciesEnablesPlugins(boolean verifyPlugins,
            boolean verifyPluginDependencies, boolean pluginsEnabled, boolean pluginDependenciesEnabled) {

        Configuration config = new Configuration(new CompositeSkipper(), new CompositeSkipper(),
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
