/*
 * Copyright 2017 Slawomir Jaranowski
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
import org.apache.maven.artifact.repository.ArtifactRepository;
import org.apache.maven.artifact.resolver.ArtifactResolutionRequest;
import org.apache.maven.artifact.resolver.ArtifactResolutionResult;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Plugin;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.apache.maven.repository.RepositorySystem;
import org.simplify4u.plugins.skipfilters.SkipFilter;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static java.util.Objects.requireNonNull;

final class ArtifactResolver {

    private RepositorySystem repositorySystem;

    private MavenProject project;

    private ArtifactRepository localRepository;

    private List<ArtifactRepository> remoteRepositories;

    private Iterable<SkipFilter> skipFilters;

    ArtifactResolver(final RepositorySystem repositorySystem,
            final MavenProject project,
            final ArtifactRepository localRepository,
            final List<ArtifactRepository> remoteRepositories,
            final Iterable<SkipFilter> skipFilters) {
        this.repositorySystem = requireNonNull(repositorySystem);
        this.project = requireNonNull(project);
        this.localRepository = requireNonNull(localRepository);
        this.remoteRepositories = requireNonNull(remoteRepositories);
        this.skipFilters = requireNonNull(skipFilters);
    }

    Set<Artifact> resolve(final Log log, final boolean verifyPomFiles) {
        final HashSet<Artifact> artifacts = new HashSet<>();
        processDependencies(log, artifacts, project.getDependencies(), verifyPomFiles);
        for (final Plugin plugin : project.getBuildPlugins()) {
            final Artifact artifact = resolve(plugin);
            // FIXME add skipping/including for build plug-ins (SNAPSHOTs)
            if (artifact.getVersion() == null) {
                // FIXME in case version is missing or version range is specified, we cannot yet resolve the exact artifact, hence cannot acquire the corresponding signature file.
                log.warn("Skipping build plugin with missing version or applying version-range: " + artifact);
                continue;
            }
            artifacts.add(artifact);
            if (verifyPomFiles) {
                artifacts.add(resolvePom(plugin));
            }
            // FIXME add configuration parameter for skipping/including dependencies of build plugins.
            processDependencies(log, artifacts, plugin.getDependencies(), verifyPomFiles);
        }
        return artifacts;
    }

    // TODO consider if we should transitively process all dependencies or trust that dependencies of dependencies are trusted based on trust in the direct dependency.
    private void processDependencies(final Log log, final Set<Artifact> destination, final Iterable<Dependency> dependencies, final boolean verifyPom) {
        for (final Dependency dependency : dependencies) {
            final Artifact artifact = resolve(dependency);
            // FIXME test skipping for various scopes.
            if (skipArtifact(artifact)) {
                log.debug("Skipping artifact: " + artifact);
                continue;
            }
            if (artifact.getVersion() == null) {
                // FIXME in case version is missing or version range is specified, we cannot yet resolve the exact artifact, hence cannot acquire the corresponding signature file.
                log.warn("Skipping artifact with missing version or applying version-range: " + artifact);
                continue;
            }
            destination.add(artifact);
            if (verifyPom) {
                destination.add(resolvePom(dependency));
            }
        }
    }

    private Artifact resolve(final Dependency dependency) {
        return resolve(repositorySystem.createDependencyArtifact(dependency));
    }

    private Artifact resolvePom(final Dependency dependency) {
        return resolve(repositorySystem.createProjectArtifact(
                dependency.getGroupId(), dependency.getArtifactId(), dependency.getVersion()));
    }

    private Artifact resolve(final Plugin plugin) {
        return resolve(repositorySystem.createPluginArtifact(plugin));
    }

    private Artifact resolvePom(final Plugin plugin) {
        return resolve(repositorySystem.createProjectArtifact(
                plugin.getGroupId(), plugin.getArtifactId(), plugin.getVersion()));
    }

    private Artifact resolve(final Artifact artifact) {
        final ArtifactResolutionRequest request = new ArtifactResolutionRequest();
        request.setArtifact(artifact);
        request.setResolveTransitively(false);
        request.setLocalRepository(localRepository);
        request.setRemoteRepositories(remoteRepositories);
        final ArtifactResolutionResult result = repositorySystem.resolve(request);
        // FIXME check result and perform exception handling in case of resolution failures.
        return artifact;
    }

    /**
     * Indicates whether or not an artifact should be skipped, based on the configuration of this
     * mojo.
     *
     * @param   artifact
     *          The artifact being considered for verification.
     *
     * @return  {@code true} if the artifact should be skipped; {@code false} if it should be
     *          processed.
     */
    private boolean skipArtifact(final Artifact artifact) {
        for (final SkipFilter filter : this.skipFilters) {
            if (filter.shouldSkipArtifact(artifact)) {
                return true;
            }
        }
        return false;
    }
}
