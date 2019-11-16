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
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.apache.maven.repository.RepositorySystem;
import org.simplify4u.plugins.skipfilters.SkipFilter;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Artifact resolver for project dependencies, build plug-ins, and build plug-in dependencies.
 */
final class ArtifactResolver {

    private final Log log;

    private final RepositorySystem repositorySystem;

    private final ArtifactRepository localRepository;

    private final List<ArtifactRepository> remoteRepositories;

    ArtifactResolver(final Log log, final RepositorySystem repositorySystem,
            final ArtifactRepository localRepository,
            final List<ArtifactRepository> remoteRepositories) {
        this.log = requireNonNull(log);
        this.repositorySystem = requireNonNull(repositorySystem);
        this.localRepository = requireNonNull(localRepository);
        this.remoteRepositories = requireNonNull(remoteRepositories);
    }

    /**
     * Types of dependencies: compile, provided, test, runtime, system, dependencies-of-build-plugins.
     *
     * @param filter         the artifact filter
     * @param verifyPomFiles indicator whether to verify POM file signatures as well
     * @return Returns set of all artifacts whose signature needs to be verified.
     */
    Set<Artifact> resolveProjectArtifacts(final MavenProject project, final SkipFilter filter, final boolean verifyPomFiles) {
        final HashSet<Artifact> artifacts = new HashSet<>(
                resolveDependencies(project.getDependencies(), filter, verifyPomFiles));
        artifacts.addAll(resolveBuildPlugins(project.getBuildPlugins(), filter, verifyPomFiles));
        return artifacts;
    }

    /**
     * Retrieves the PGP signature file that corresponds to the given Maven artifact.
     *
     * @param   artifacts
     *          The artifacts for which a signatures are desired.
     * @return  Either a Maven artifact for the signature file, or {@code null} if the signature
     *          file could not be retrieved.
     *
     * @throws MojoExecutionException
     *          If the signature could not be retrieved and the Mojo has been configured to fail
     *          on a missing signature.
     */
    Map<Artifact, Artifact> resolveSignatures(final Set<Artifact> artifacts, final SignatureRequirement requirement) throws MojoExecutionException {
        log.debug("Start resolving ASC files");

        final HashMap<Artifact, Artifact> artifactToAsc = new HashMap<>();
        for (Artifact artifact : artifacts) {
            final Artifact ascArtifact = resolveSignature(artifact, requirement);

            if (ascArtifact != null || requirement == SignatureRequirement.STRICT) {
                artifactToAsc.put(artifact, ascArtifact);
            }
        }

        return artifactToAsc;
    }

    private Set<Artifact> resolveBuildPlugins(final Iterable<Plugin> plugins, final SkipFilter filter, final boolean verifyPom) {
        final HashSet<Artifact> collection = new HashSet<>();
        for (final Plugin plugin : plugins) {
            final Artifact artifact = resolve(plugin);
            // FIXME add skipping/including for build plug-ins (SNAPSHOTs)
            if (artifact.getVersion() == null) {
                // FIXME in case version is missing or version range is specified, we cannot yet resolve the exact artifact, hence cannot acquire the corresponding signature file.
                log.warn("Skipping build plugin with missing version or applying version-range: " + artifact);
                continue;
            }
            collection.add(artifact);
            if (verifyPom) {
                // FIXME check how to treat missing POM files.
                collection.add(resolvePom(plugin));
            }
            // FIXME add configuration parameter for skipping/including dependencies of build plugins.
            collection.addAll(resolveDependencies(plugin.getDependencies(), filter, verifyPom));
        }
        return collection;
    }

    // TODO consider if we should transitively process all dependencies or trust that dependencies of dependencies are trusted based on trust in the direct dependency.
    private Set<Artifact> resolveDependencies(final Iterable<Dependency> dependencies, final SkipFilter filter, final boolean verifyPom) {
        final HashSet<Artifact> collection = new HashSet<>();
        for (final Dependency dependency : dependencies) {
            final Artifact artifact = resolve(dependency);
            // FIXME test skipping for various scopes.
            if (filter.shouldSkipArtifact(artifact)) {
                log.debug("Skipping artifact: " + artifact);
                continue;
            }
            if (artifact.getVersion() == null) {
                // FIXME in case version is missing or version range is specified, we cannot yet resolve the exact artifact, hence cannot acquire the corresponding signature file.
                log.warn("Skipping artifact with missing version or applying version-range: " + artifact);
                continue;
            }
            collection.add(artifact);
            if (verifyPom) {
                // FIXME check how to treat missing POM files.
                collection.add(resolvePom(dependency));
            }
        }
        return collection;
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

    private Artifact resolveSignature(final Artifact artifact, final SignatureRequirement requirement) throws MojoExecutionException {
        final Artifact aAsc = repositorySystem.createArtifactWithClassifier(
                artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion(),
                artifact.getType(), artifact.getClassifier());
        aAsc.setArtifactHandler(new AscArtifactHandler(aAsc));

        // FIXME consider if we need to re-acquire the artifact from the request in order for version (range) resolution to have been performed.
        final ArtifactResolutionResult ascResult = request(aAsc);
        if (ascResult.isSuccess()) {
            log.debug(aAsc.toString() + " " + aAsc.getFile());
            return aAsc;
        }

        switch (requirement) {
        case NONE:
            log.warn("No signature for " + artifact.getId());
            break;
        case STRICT:
            // no action needed here
            break;
        case REQUIRED:
            log.error("No signature for " + artifact.getId());
            throw new MojoExecutionException("No signature for " + artifact.getId());
        default:
            throw new UnsupportedOperationException("Unsupported signature requirement.");
        }

        return null;
    }

    private Artifact resolve(final Artifact artifact) {
        final ArtifactResolutionResult result = request(artifact);
        // FIXME perform result verification before returning artifact.
        return artifact;
    }

    private ArtifactResolutionResult request(final Artifact artifact) {
        final ArtifactResolutionRequest request = new ArtifactResolutionRequest();
        request.setArtifact(artifact);
        request.setResolveTransitively(false);
        request.setLocalRepository(localRepository);
        request.setRemoteRepositories(remoteRepositories);
        final ArtifactResolutionResult result = repositorySystem.resolve(request);
        System.err.println("Artifact after request: " + request.getArtifact());
        return result;
    }

    enum SignatureRequirement {
        NONE,
        STRICT,
        REQUIRED,
    }
}
