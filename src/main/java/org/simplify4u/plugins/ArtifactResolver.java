/*
 * Copyright 2019 Slawomir Jaranowski
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

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;
import static java.util.stream.StreamSupport.stream;

/**
 * Artifact resolver for project dependencies, build plug-ins, and build plug-in dependencies.
 */
final class ArtifactResolver {

    private final Log log;

    private final RepositorySystem repositorySystem;

    private final ArtifactRepository localRepository;

    private final List<ArtifactRepository> remoteRepositories;

    ArtifactResolver(Log log, RepositorySystem repositorySystem, ArtifactRepository localRepository,
            final List<ArtifactRepository> remoteRepositories) {
        this.log = requireNonNull(log);
        this.repositorySystem = requireNonNull(repositorySystem);
        this.localRepository = requireNonNull(localRepository);
        this.remoteRepositories = requireNonNull(remoteRepositories);
    }

    /**
     * Types of dependencies: compile, provided, test, runtime, system, dependencies of build plug-ins.
     *
     * @param filter         the artifact filter
     * @param verifyPomFiles indicator whether to verify POM file signatures as well
     * @return Returns set of all artifacts whose signature needs to be verified.
     */
    Set<Artifact> resolveProjectArtifacts(MavenProject project, SkipFilter filter, boolean verifyPomFiles)
            throws MojoExecutionException {
        final Set<Artifact> allArtifacts = resolveDependencies(project.getDependencies(), filter, verifyPomFiles);
        allArtifacts.addAll(resolveBuildPlugins(project.getBuildPlugins(), filter, verifyPomFiles));
        return updateArtifactResolvedVersions(allArtifacts, project.getArtifacts());
    }

    /**
     * Update provided artifacts with artifact versions as provided in input.
     *
     * @param allArtifacts             the full set of artifacts.
     * @param projectResolvedArtifacts a separate set of artifacts with versions as resolved by dependency resolution.
     *                                 Input is expected to have significant overlap, but may contain deviations such as
     *                                 missing artifacts.
     * @return Returns set of artifacts with versions updated according to provided input set.
     * @throws MojoExecutionException In case of failure to resolve artifact both through dependency resolution process
     * and manual resolving.
     */
    private Set<Artifact> updateArtifactResolvedVersions(Iterable<Artifact> allArtifacts,
            Iterable<Artifact> projectResolvedArtifacts) throws MojoExecutionException {
        final LinkedHashSet<Artifact> result = new LinkedHashSet<>();
        for (final Artifact artifact : allArtifacts) {
            final Optional<Artifact> projectResolved = stream(projectResolvedArtifacts.spliterator(), false)
                    .filter(a -> a.getArtifactId().equals(artifact.getArtifactId()))
                    .filter(a -> a.getGroupId().equals(artifact.getGroupId()))
                    .findFirst();
            if (projectResolved.isPresent()) {
                // add artifact with version as resolved by Maven dependency resolution
                artifact.setVersion(projectResolved.get().getVersion());
                result.add(resolve(artifact));
            } else if (artifact.isResolved()) {
                // add artifact with listed version
                result.add(artifact);
            } else {
                // failed to resolve artifact with definite version
                throw new MojoExecutionException("Failed to determine definite version for artifact " + artifact);
            }
        }
        return result;
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
    Map<Artifact, Artifact> resolveSignatures(Iterable<Artifact> artifacts, SignatureRequirement requirement)
            throws MojoExecutionException {
        log.debug("Start resolving ASC files");

        final LinkedHashMap<Artifact, Artifact> artifactToAsc = new LinkedHashMap<>();
        for (Artifact artifact : artifacts) {
            final Artifact ascArtifact = resolveSignature(artifact, requirement);

            if (ascArtifact != null || requirement == SignatureRequirement.STRICT) {
                artifactToAsc.put(artifact, ascArtifact);
            }
        }

        return artifactToAsc;
    }

    /**
     * Resolve build plug-ins.
     *
     * @param plugins   The build plug-ins to be resolved.
     * @param filter    The skip filter.
     * @param verifyPom Boolean indicating whether or not to resolve corresponding POMs.
     * @return Returns resolved build plug-in artifacts.
     */
    private Set<Artifact> resolveBuildPlugins(Iterable<Plugin> plugins, SkipFilter filter, boolean verifyPom) throws MojoExecutionException {
        final LinkedHashSet<Artifact> collection = new LinkedHashSet<>();
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

    /**
     * Resolve all dependencies provided as input. POMs corresponding to the dependencies may optionally be resolved.
     *
     * @param dependencies Dependencies to be resolved.
     * @param filter       Skip filter to test against to determine whether dependency must be skipped.
     * @param verifyPom    Boolean indicating whether or not POMs corresponding to dependencies should be resolved.
     * @return Returns set of resolved artifacts, which may contain artifacts of which the definite version cannot be
     * determined yet.
     */
    // TODO consider if we should transitively process all dependencies or trust that dependencies of dependencies are trusted based on trust in the direct dependency.
    private Set<Artifact> resolveDependencies(Iterable<Dependency> dependencies, SkipFilter filter, boolean verifyPom) {
        final LinkedHashSet<Artifact> collection = new LinkedHashSet<>();
        for (final Dependency dependency : dependencies) {
            final Artifact artifact = resolve(dependency);
            // FIXME test skipping for various scopes.
            if (filter.shouldSkipArtifact(artifact)) {
                log.debug("Skipping artifact: " + artifact);
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

    private Artifact resolve(Dependency dependency) {
        return resolve(repositorySystem.createDependencyArtifact(dependency));
    }

    private Artifact resolvePom(Dependency dependency) {
        return resolve(repositorySystem.createProjectArtifact(
                dependency.getGroupId(), dependency.getArtifactId(), dependency.getVersion()));
    }

    private Artifact resolve(Plugin plugin) {
        return resolve(repositorySystem.createPluginArtifact(plugin));
    }

    private Artifact resolvePom(Plugin plugin) {
        return resolve(repositorySystem.createProjectArtifact(
                plugin.getGroupId(), plugin.getArtifactId(), plugin.getVersion()));
    }

    private Artifact resolveSignature(Artifact artifact, SignatureRequirement requirement) throws MojoExecutionException {
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

    private Artifact resolve(Artifact artifact) {
        request(artifact);
        // Evaluation of resolution results of all artifacts is done at a later stage,
        // as resolution is performed in multiple stages.
        return artifact;
    }

    private ArtifactResolutionResult request(Artifact artifact) {
        final ArtifactResolutionRequest request = new ArtifactResolutionRequest();
        request.setArtifact(artifact);
        request.setResolveTransitively(false);
        request.setLocalRepository(localRepository);
        request.setRemoteRepositories(remoteRepositories);
        return repositorySystem.resolve(request);
    }

    enum SignatureRequirement {
        NONE,
        STRICT,
        REQUIRED,
    }
}
