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
package org.simplify4u.plugins.utils;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.model.Plugin;
import org.apache.maven.repository.RepositorySystem;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static java.util.Collections.emptySet;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.simplify4u.plugins.utils.MavenCompilerUtils.checkCompilerPlugin;
import static org.simplify4u.plugins.utils.MavenCompilerUtils.extractAnnotationProcessors;

@SuppressWarnings({"ConstantConditions", "SameParameterValue"})
final class MavenCompilerUtilsTest {

    @Test
    void testCheckCompilerPlugin() {
        assertThrows(NullPointerException.class, () -> checkCompilerPlugin(null));
        final Plugin compilerPlugin = mock(Plugin.class);
        when(compilerPlugin.getGroupId()).thenReturn("org.apache.maven.plugins");
        when(compilerPlugin.getArtifactId()).thenReturn("maven-compiler-plugin");
        when(compilerPlugin.getVersion()).thenReturn("3.8.1");
        assertTrue(checkCompilerPlugin(compilerPlugin));
        final Plugin otherPlugin = mock(Plugin.class);
        when(otherPlugin.getGroupId()).thenReturn("org.apache.maven.plugin");
        when(otherPlugin.getArtifactId()).thenReturn("some-other-plugin");
        when(otherPlugin.getVersion()).thenReturn("3.5.9");
        assertFalse(checkCompilerPlugin(otherPlugin));
    }

    @Test
    void testExtractAnnotationProcessorsIllegalInputs() {
        assertThrows(NullPointerException.class, () -> extractAnnotationProcessors(null));
        final Plugin badPlugin = mock(Plugin.class);
        when(badPlugin.getGroupId()).thenReturn("org.my-bad-plugin");
        when(badPlugin.getArtifactId()).thenReturn("bad-plugin");
        when(badPlugin.getVersion()).thenReturn("1.1.1");
        assertThrows(NullPointerException.class, () -> extractAnnotationProcessors(null));
        assertThrows(IllegalArgumentException.class, () -> extractAnnotationProcessors( badPlugin));
    }

    @Test
    void testExtractAnnotationProcessorsNoConfiguration() {
        final Plugin plugin = mock(Plugin.class);
        when(plugin.getGroupId()).thenReturn("org.apache.maven.plugins");
        when(plugin.getArtifactId()).thenReturn("maven-compiler-plugin");
        when(plugin.getVersion()).thenReturn("3.8.1");
        assertEquals(emptySet(), extractAnnotationProcessors(plugin));
    }

    @Test
    void testExtractAnnotationProcessorsUnsupportedConfigurationType() {
        final Plugin plugin = mock(Plugin.class);
        when(plugin.getGroupId()).thenReturn("org.apache.maven.plugins");
        when(plugin.getArtifactId()).thenReturn("maven-compiler-plugin");
        when(plugin.getVersion()).thenReturn("3.8.1");
        when(plugin.getConfiguration()).thenReturn("Massive configuration encoded in magic \"Hello World!\" string.");
        assertThrows(UnsupportedOperationException.class, () -> extractAnnotationProcessors(plugin));
    }

    @Test
    void testExtractAnnotationProcessors() {
        final RepositorySystem repository = mock(RepositorySystem.class);
        final Plugin plugin = mock(Plugin.class);
        when(plugin.getGroupId()).thenReturn("org.apache.maven.plugins");
        when(plugin.getArtifactId()).thenReturn("maven-compiler-plugin");
        when(plugin.getVersion()).thenReturn("3.8.1");
        when(plugin.getConfiguration()).thenReturn(createConfiguration());
        when(repository.createArtifact(anyString(), anyString(), anyString(), anyString())).thenAnswer(invocation -> {
            final Artifact artifact = mock(Artifact.class);
            when(artifact.getGroupId()).thenReturn(invocation.getArgument(0));
            when(artifact.getArtifactId()).thenReturn(invocation.getArgument(1));
            when(artifact.getVersion()).thenReturn(invocation.getArgument(2));
            return artifact;
        });
        final Set<org.eclipse.aether.artifact.Artifact> result = extractAnnotationProcessors(plugin);
        assertEquals(1, result.size());
        final org.eclipse.aether.artifact.Artifact resultElement = result.iterator().next();
        assertEquals("myGroupId", resultElement.getGroupId());
        assertEquals("myArtifactId", resultElement.getArtifactId());
        assertEquals("1.2.3", resultElement.getVersion());
    }

    private static Xpp3Dom createConfiguration() {
        final Xpp3Dom config = new Xpp3Dom("configuration");
        final Xpp3Dom annotationProcessorPaths = new Xpp3Dom("annotationProcessorPaths");
        annotationProcessorPaths.addChild(createPath("myGroupId", "myArtifactId", "1.2.3"));
        annotationProcessorPaths.addChild(createPath("", "myArtifactId", "1.2.3"));
        annotationProcessorPaths.addChild(createPath("myGroupId", "", "1.2.3"));
        annotationProcessorPaths.addChild(createPath(null, "myArtifactId", "1.2.3"));
        annotationProcessorPaths.addChild(createPath("myGroupId", null, "1.2.3"));
        annotationProcessorPaths.addChild(createPath("myGroupId", "myArtifactId", null));
        config.addChild(annotationProcessorPaths);
        return config;
    }

    private static Xpp3Dom createPath(String groupId, String artifactId, String version) {
        final Xpp3Dom path = new Xpp3Dom("path");
        if (groupId != null) {
            final Xpp3Dom groupIdNode = new Xpp3Dom("groupId");
            groupIdNode.setValue(groupId);
            path.addChild(groupIdNode);
        }
        if (artifactId != null) {
            final Xpp3Dom artifactIdNode = new Xpp3Dom("artifactId");
            artifactIdNode.setValue(artifactId);
            path.addChild(artifactIdNode);
        }
        if (version != null) {
            final Xpp3Dom versionNode = new Xpp3Dom("version");
            versionNode.setValue(version);
            path.addChild(versionNode);
        }
        return path;
    }
}