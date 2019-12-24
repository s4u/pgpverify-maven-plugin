/*
 * Copyright 2019 Slawomir Jaranowski
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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.repository.ArtifactRepository;
import org.apache.maven.artifact.repository.ArtifactRepositoryPolicy;
import org.apache.maven.artifact.resolver.ArtifactResolutionRequest;
import org.apache.maven.artifact.resolver.ArtifactResolutionResult;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.apache.maven.repository.RepositorySystem;
import org.simplify4u.plugins.skipfilters.SkipFilter;

/**
 * Artifact resolver for project dependencies, build plug-ins, and build plug-in dependencies.
 */
final class ArtifactResolver {

    private final Log log;

    private final RepositorySystem repositorySystem;

    private final ArtifactRepository localRepository;

    private final List<ArtifactRepository> remoteRepositories;

    /**
     * Copy of remote repositories with check sum policy set to ignore,
     * we need it for pgp signature resolving.
     *
     * pgp signature *.asc is signature so there is'n signature for signature
     */
    private final List<ArtifactRepository> remoteRepositoriesIgnoreCheckSum;

    ArtifactResolver(Log log, RepositorySystem repositorySystem, ArtifactRepository localRepository,
                     List<ArtifactRepository> remoteRepositories) {
        this.log = requireNonNull(log);
        this.repositorySystem = requireNonNull(repositorySystem);
        this.localRepository = requireNonNull(localRepository);
        this.remoteRepositories = requireNonNull(remoteRepositories);

        this.remoteRepositoriesIgnoreCheckSum = repositoriesIgnoreCheckSum(remoteRepositories);
    }

    /**
     * Wrap remote repository with ignore check sum policy.
     *
     * @param repositories
     *         list to wrap
     *
     * @return wrapped repository list
     */
    private List<ArtifactRepository> repositoriesIgnoreCheckSum(List<ArtifactRepository> repositories) {

        return Optional.ofNullable(repositories)
                .orElse(Collections.emptyList())
                .stream()
                .map(this::repositoryIgnoreCheckSum)
                .collect(Collectors.toList());
    }

    private ArtifactRepository repositoryIgnoreCheckSum(ArtifactRepository repository) {

        ArtifactRepository newRepository = repositorySystem.createArtifactRepository(
                repository.getId(), repository.getUrl(), repository.getLayout(),
                policyIgnoreCheckSum(repository.getSnapshots()),
                policyIgnoreCheckSum(repository.getReleases()));

        newRepository.setAuthentication(repository.getAuthentication());
        newRepository.setProxy(repository.getProxy());
        newRepository.setMirroredRepositories(repositoriesIgnoreCheckSum(repository.getMirroredRepositories()));

        return newRepository;
    }

    private ArtifactRepositoryPolicy policyIgnoreCheckSum(ArtifactRepositoryPolicy policy) {
        return new ArtifactRepositoryPolicy(policy.isEnabled(), policy.getUpdatePolicy(), "ignore");
    }

    /**
     * Types of dependencies: compile, provided, test, runtime, system, maven-plugin.
     *
     * @param filter
     *         the artifact filter
     * @param verifyPomFiles
     *         indicator whether to verify POM file signatures as well
     *
     * @return Returns set of all artifacts whose signature needs to be verified.
     */
    Set<Artifact> resolveProjectArtifacts(MavenProject project, SkipFilter filter, boolean verifyPomFiles,
                                          boolean verifyPlugins) throws MojoExecutionException {
        final LinkedHashSet<Artifact> allArtifacts = new LinkedHashSet<>(
                resolveArtifacts(project.getArtifacts(), filter, verifyPomFiles));
        if (verifyPlugins) {
            allArtifacts.addAll(resolveArtifacts(project.getPluginArtifacts(), filter, verifyPomFiles));
            // Maven does not allow specifying version ranges for build plug-in
            // dependencies, therefore we can use the literal specified
            // dependency.
            // TODO: only immediate plug-in dependencies are validated. Indirect dependencies are not validated yet.
            allArtifacts.addAll(resolveArtifacts(
                    project.getBuildPlugins().stream()
                            .flatMap(p -> p.getDependencies().stream())
                            .map(repositorySystem::createDependencyArtifact)
                            .collect(Collectors.toList()),
                    filter, verifyPomFiles));
            // TODO: there is a common special source of additional jars: maven-compiler-plugin's annotationProcessorPaths configuration section, which references jars to be loaded as annotation processors.
        }
        log.debug("Discovered project artifacts: " + allArtifacts);
        return allArtifacts;
    }

    /**
     * Retrieves the PGP signature file that corresponds to the given Maven artifact.
     *
     * @param artifacts
     *         The artifacts for which a signatures are desired.
     *
     * @return Either a Maven artifact for the signature file, or {@code null} if the signature
     * file could not be retrieved.
     *
     * @throws MojoExecutionException
     *         If the signature could not be retrieved and the Mojo has been configured to fail
     *         on a missing signature.
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

    private Artifact resolveSignature(Artifact artifact, SignatureRequirement requirement)
            throws MojoExecutionException {
        final Artifact aAsc = repositorySystem.createArtifactWithClassifier(
                artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion(),
                artifact.getType(), artifact.getClassifier());
        aAsc.setArtifactHandler(new AscArtifactHandler(aAsc));

        final ArtifactResolutionResult ascResult = request(aAsc, remoteRepositoriesIgnoreCheckSum);
        if (ascResult.isSuccess()) {
            log.debug(aAsc.toString() + " " + aAsc.getFile());
            return aAsc;
        }

        switch (requirement) {
            case NONE:
                log.warn("No signature for " + artifact.getId());
                break;
            case STRICT:
                log.debug("No signature for " + artifact.getId());
                // no action needed here. If we need to show a warning message,
                // we will determine this when verifying signatures (or lack thereof)
                break;
            case REQUIRED:
                log.error("No signature for " + artifact.getId());
                throw new MojoExecutionException("No signature for " + artifact.getId());
            default:
                throw new UnsupportedOperationException("Unsupported signature requirement.");
        }

        return null;
    }

    /**
     * Resolve all dependencies provided as input. POMs corresponding to the dependencies may optionally be resolved.
     *
     * @param artifacts
     *         Dependencies to be resolved.
     * @param filter
     *         Skip filter to test against to determine whether dependency must be skipped.
     * @param verifyPom
     *         Boolean indicating whether or not POMs corresponding to dependencies should be resolved.
     *
     * @return Returns set of resolved artifacts, which may contain artifacts of which the definite version cannot be
     * determined yet.
     */
    private Set<Artifact> resolveArtifacts(Iterable<Artifact> artifacts, SkipFilter filter, boolean verifyPom)
            throws MojoExecutionException {
        final LinkedHashSet<Artifact> collection = new LinkedHashSet<>();
        for (final Artifact artifact : artifacts) {
            final Artifact resolved = resolveArtifact(artifact);
            if (filter.shouldSkipArtifact(artifact)) {
                log.debug("Skipping artifact: " + artifact);
                continue;
            }
            if (!resolved.isResolved()) {
                throw new MojoExecutionException("Failed to resolve artifact: " + artifact);
            }
            collection.add(resolved);
            if (verifyPom) {
                final Artifact resolvedPom = resolvePom(artifact);
                if (resolvedPom.isResolved()) {
                    collection.add(resolvedPom);
                } else {
                    log.warn("Failed to resolve pom artifact: " + resolvedPom);
                }
            }
        }
        return collection;
    }

    private Artifact resolvePom(Artifact artifact) {
        final Artifact pomArtifact = repositorySystem.createProjectArtifact(artifact.getGroupId(),
                artifact.getArtifactId(), artifact.getVersion());
        final ArtifactResolutionResult result = request(pomArtifact, remoteRepositories);
        if (!result.isSuccess()) {
            result.getExceptions().forEach(
                    e -> log.debug("Failed to resolve pom " + pomArtifact.getId() + ": " + e.getMessage()));
        }
        return pomArtifact;
    }

    private Artifact resolveArtifact(Artifact artifact) {
        final ArtifactResolutionResult result = request(artifact, remoteRepositories);
        if (!result.isSuccess()) {
            result.getExceptions().forEach(e -> {
                log.warn("Failed to resolve " + artifact.getId() + ": " + e.getMessage());
                log.debug(e);
            });
        }
        return artifact;
    }

    private ArtifactResolutionResult request(Artifact artifact, List<ArtifactRepository> remoteRepositoriesToResolve) {
        final ArtifactResolutionRequest request = new ArtifactResolutionRequest();
        request.setArtifact(artifact);
        request.setResolveTransitively(false);
        request.setLocalRepository(localRepository);
        request.setRemoteRepositories(remoteRepositoriesToResolve);

        return repositorySystem.resolve(request);
    }

    /**
     * Enum specifying the levels of signature requirements.
     */
    enum SignatureRequirement {
        /**
         * NONE indicates there are no requirements, meaning that missing
         * signatures are perfectly acceptable.
         */
        NONE,
        /**
         * STRICT indicates that requirements of signatures (availability) are
         * defined per artifact according to the keys map.
         */
        STRICT,
        /**
         * REQUIRED indicates that signatures are strictly required, meaning
         * that missing signature is an immediate failure case.
         */
        REQUIRED,
    }
}
