/*
 * Copyright 2019-2021 Slawomir Jaranowski
 * Portions Copyright 2019-2020 Danny van Heumen
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

import javax.inject.Inject;
import javax.inject.Named;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import io.vavr.control.Try;
import org.apache.maven.RepositoryUtils;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.repository.ArtifactRepository;
import org.apache.maven.artifact.resolver.ArtifactResolutionRequest;
import org.apache.maven.artifact.resolver.ArtifactResolutionResult;
import org.apache.maven.artifact.resolver.filter.ArtifactFilter;
import org.apache.maven.artifact.versioning.VersionRange;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Plugin;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.repository.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.RequestTrace;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.repository.RepositoryPolicy;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.ArtifactResult;
import org.eclipse.aether.util.artifact.SubArtifact;
import org.simplify4u.plugins.skipfilters.CompositeSkipper;
import org.simplify4u.plugins.skipfilters.ScopeSkipper;
import org.simplify4u.plugins.skipfilters.SkipFilter;
import org.simplify4u.plugins.utils.MavenCompilerUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.Collections.singleton;
import static java.util.Objects.requireNonNull;
import static org.simplify4u.plugins.utils.MavenCompilerUtils.extractAnnotationProcessors;

/**
 * Artifact resolver for project dependencies, build plug-ins, and build plug-in dependencies.
 */
@Named
public class ArtifactResolver {

    private static final Logger LOG = LoggerFactory.getLogger(ArtifactResolver.class);

    private static final VersionRange SUREFIRE_PLUGIN_VERSION_RANGE = Try.of(
                    () -> VersionRange.createFromVersionSpec("(2.999999999,4)"))
            .getOrElseThrow(e -> new IllegalStateException("BUG: Failed to create version range.", e));

    private final RepositorySystem repositorySystem;

    private final org.eclipse.aether.RepositorySystem aetherRepositorySystem;

    private final RepositorySystemSession repositorySession;

    private final ArtifactRepository localRepository;

    private final List<ArtifactRepository> remoteRepositories;

    private final List<RemoteRepository> aeRemoteRepositories;

    /**
     * Copy of remote repositories with check sum policy set to ignore, we need it for pgp signature resolving.
     * <p>
     * pgp signature *.asc is signature so there is'n signature for signature
     */
    private final List<RemoteRepository> remoteRepositoriesIgnoreCheckSum;

    @Inject
    ArtifactResolver(RepositorySystem repositorySystem, MavenSession session,
                     org.eclipse.aether.RepositorySystem aetherRepositorySystem) {
        this.repositorySystem = requireNonNull(repositorySystem);
        this.localRepository = requireNonNull(session.getLocalRepository());
        this.remoteRepositories = requireNonNull(session.getCurrentProject().getRemoteArtifactRepositories());
        this.aeRemoteRepositories = requireNonNull(session.getCurrentProject().getRemoteProjectRepositories());
        this.remoteRepositoriesIgnoreCheckSum =
                repositoriesIgnoreCheckSum(session.getCurrentProject().getRemoteProjectRepositories());
        this.aetherRepositorySystem = aetherRepositorySystem;
        this.repositorySession = session.getRepositorySession();
    }

    /**
     * Wrap remote repository with ignore check sum policy.
     *
     * @param repositories list to wrap
     * @return wrapped repository list
     */
    private static List<RemoteRepository> repositoriesIgnoreCheckSum(List<RemoteRepository> repositories) {

        return Optional.ofNullable(repositories)
                .orElse(Collections.emptyList())
                .stream()
                .map(ArtifactResolver::repositoryIgnoreCheckSum)
                .collect(Collectors.toList());
    }

    private static RemoteRepository repositoryIgnoreCheckSum(RemoteRepository repository) {

        RepositoryPolicy snapshotPolicy = repository.getPolicy(true);
        RepositoryPolicy releasePolicy = repository.getPolicy(false);

        RemoteRepository.Builder builder = new RemoteRepository.Builder(repository);
        builder.setSnapshotPolicy(policyIgnoreCheckSum(snapshotPolicy));
        builder.setReleasePolicy(policyIgnoreCheckSum(releasePolicy));

        return builder.build();
    }

    private static RepositoryPolicy policyIgnoreCheckSum(RepositoryPolicy policy) {
        return new RepositoryPolicy(policy.isEnabled(), policy.getUpdatePolicy(),
                RepositoryPolicy.CHECKSUM_POLICY_IGNORE);
    }

    /**
     * Types of dependencies: compile, provided, test, runtime, system, maven-plugin.
     *
     * @param project the maven project instance
     * @param config  configuration for the artifact resolver
     * @return Returns set of all artifacts whose signature needs to be verified.
     */
    //    @SuppressWarnings( {"deprecation", "java:S1874"})
    Set<Artifact> resolveProjectArtifacts(MavenProject project, Configuration config) throws MojoExecutionException {

        final LinkedHashSet<Artifact> allArtifacts = new LinkedHashSet<>(resolveProjectArtifacts(project.getArtifacts(),
                config.dependencyFilter, config.verifyPomFiles));

        if (config.verifyPlugins) {
            // Resolve transitive dependencies for build plug-ins and reporting plug-ins and their dependencies.
            // The transitive closure is computed for each plug-in with its dependencies, as individual executions may
            // depend on a different version of a particular dependency. Therefore, a dependency may be included in the
            // over-all artifacts list multiple times with different versions.
            for (final Plugin plugin : project.getBuildPlugins()) {
                final LinkedHashSet<Artifact> artifacts = new LinkedHashSet<>();
                artifacts.add(repositorySystem.createPluginArtifact(plugin));
                artifacts.addAll(plugin.getDependencies().stream()
                        .map(repositorySystem::createDependencyArtifact)
                        .collect(Collectors.toSet()));
                final Set<Artifact> resolved = resolveArtifacts(artifacts, config.pluginFilter, config.dependencyFilter,
                        config.verifyPomFiles, config.verifyPluginDependencies);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Build plugin dependencies for {}:{}:{} {}", plugin.getGroupId(), plugin.getArtifactId(),
                            plugin.getVersion(), resolved);
                }
                allArtifacts.addAll(resolved);
            }
            for (final Artifact plugin : project.getReportArtifacts()) {
                final Set<Artifact> resolved = resolveArtifacts(singleton(plugin), config.pluginFilter,
                        config.dependencyFilter, config.verifyPomFiles, config.verifyPluginDependencies);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Report plugin dependencies for {}:{}:{} {}", plugin.getGroupId(), plugin.getArtifactId(),
                            plugin.getVersion(), resolved);
                }
                allArtifacts.addAll(resolved);
            }
        }
        if (config.verifyAtypical) {
            // Verify artifacts in atypical locations, such as references in configuration.
            allArtifacts.addAll(resolveArtifacts(searchCompilerAnnotationProcessors(project),
                    config.dependencyFilter, config.dependencyFilter, config.verifyPomFiles,
                    config.verifyPluginDependencies));
            informSurefire3RuntimeDependencyLoadingLimitation(project);
        }
        return allArtifacts;
    }

    private Collection<Artifact> searchCompilerAnnotationProcessors(MavenProject project) {
        return project.getBuildPlugins().stream()
                .filter(MavenCompilerUtils::checkCompilerPlugin)
                .flatMap(p -> extractAnnotationProcessors(repositorySystem, p).stream())
                .collect(Collectors.toList());
    }

    /**
     * Inform user of limitation with respect to validation of maven-surefire-plugin.
     *
     * <p>
     * Maven's Surefire plug-in version 3 resolves and loads dependencies at run-time for unit testing frameworks that
     * are present in the project. The resolution for these dependencies happens at a later stage and therefore
     * pgpverify will not automagically detect their presence.
     *
     * <p>
     * For now, we inform the user of this limitation such that the user is informed until a better solution is
     * implemented.
     *
     * <p>
     * More information on what dependencies are resolved and loaded at execution time by maven-surefire-plugin, one
     * needs to run maven-surefire-plugin with debug output enabled. Surefire will list a "provider classpath" which is
     * dynamically composed out of the frameworks it detected.
     *
     * <p>
     * For example, in case the JUnit4 framework is present.
     * <pre>
     * [DEBUG] provider(compact) classpath:  surefire-junit47-3.0.0-M3.jar  surefire-api-3.0.0-M3.jar
     * surefire-logger-api-3.0.0-M3.jar  common-java5-3.0.0-M3.jar  common-junit3-3.0.0-M3.jar
     * common-junit4-3.0.0-M3.jar  common-junit48-3.0.0-M3.jar  surefire-grouper-3.0.0-M3.jar
     * </pre>
     *
     * @param project maven project instance
     */
    // TODO: maven-surefire-plugin dependency loading during execution is detected but not handled. Some of surefire's
    //  dependencies are not validated.
    private void informSurefire3RuntimeDependencyLoadingLimitation(MavenProject project) {
        final boolean surefireDynamicLoadingLikely = project.getBuildPlugins().stream()
                .filter(p -> "org.apache.maven.plugins".equals(p.getGroupId()))
                .filter(p -> "maven-surefire-plugin".equals(p.getArtifactId()))
                .anyMatch(this::matchSurefireVersion);
        if (surefireDynamicLoadingLikely) {
            LOG.info("NOTE: maven-surefire-plugin version 3 is present. This version is known to resolve " +
                    "and load dependencies for various unit testing frameworks (called \"providers\") during " +
                    "execution. These dependencies are not validated.");
        }
    }

    private boolean matchSurefireVersion(Plugin plugin) {

        return Try.of(() -> repositorySystem.createPluginArtifact(plugin).getSelectedVersion())
                .map(SUREFIRE_PLUGIN_VERSION_RANGE::containsVersion)
                .onFailure(e -> LOG.debug("Found build plug-in with overly constrained version specification.", e))
                .getOrElse(false);
    }

    /**
     * Retrieves the PGP signature file that corresponds to the given Maven artifact.
     *
     * @param artifacts The artifacts for which a signatures are desired.
     * @return Map artifact to signature
     */
    Map<Artifact, Artifact> resolveSignatures(Collection<Artifact> artifacts) {

        List<ArtifactRequest> requestList = new ArrayList<>();
        artifacts.forEach(a -> {
            String version = a.getVersion();
            if (version == null && a.getVersionRange() != null) {
                version = a.getVersionRange().toString();
            }
            DefaultArtifact artifact = new DefaultArtifact(a.getGroupId(), a.getArtifactId(), a.getClassifier(),
                    a.getArtifactHandler().getExtension() + ".asc", version);

            ArtifactRequest request = new ArtifactRequest(artifact, remoteRepositoriesIgnoreCheckSum, null);
            request.setTrace(new RequestTrace(a));
            requestList.add(request);
        });

        Map<Artifact, Artifact> result = new HashMap<>();

        List<ArtifactResult> artifactResults =
                Try.of(() -> aetherRepositorySystem.resolveArtifacts(repositorySession, requestList))
                        .recover(ArtifactResolutionException.class, ArtifactResolutionException::getResults)
                        .get();

        artifactResults.forEach(aResult -> {
            Artifact ascArtifact = RepositoryUtils.toArtifact(aResult.getArtifact());
            Artifact artifact = (Artifact) aResult.getRequest().getTrace().getData();
            if (!aResult.isResolved()) {
                aResult.getExceptions().forEach(
                        e -> LOG.debug("Failed to resolve asc {}: {}", aResult.getRequest().getArtifact(),
                                e.getMessage()));
            }
            result.put(artifact, ascArtifact);
        });

        return result;
    }

    /**
     * Resolve all dependencies provided as input. POMs corresponding to the dependencies may optionally be resolved.
     *
     * @param artifacts      Dependencies to be resolved.
     * @param artifactFilter Skip filter to test against to determine whether dependency must be skipped.
     * @param verifyPom      Boolean indicating whether or not POMs corresponding to dependencies should be
     *                       resolved.
     * @return Returns set of resolved artifacts.
     */
    private Set<Artifact> resolveProjectArtifacts(Iterable<Artifact> artifacts, SkipFilter artifactFilter,
                                                  boolean verifyPom) {
        final LinkedHashSet<org.eclipse.aether.artifact.Artifact> collection = new LinkedHashSet<>();
        for (Artifact artifact : artifacts) {
            if (artifactFilter.shouldSkipArtifact(artifact)) {
                LOG.debug("Skipping artifact: {}", artifact);
                continue;
            }
            org.eclipse.aether.artifact.Artifact aeArtifact = RepositoryUtils.toArtifact(artifact);
            collection.add(aeArtifact);
            if (verifyPom) {
                SubArtifact pomArtifact = new SubArtifact(aeArtifact, null, "pom");
                collection.add(pomArtifact);
            }
        }

        List<ArtifactRequest> requestList = collection.stream()
                .map(a -> new ArtifactRequest(a, aeRemoteRepositories, null))
                .collect(Collectors.toList());

        List<ArtifactResult> artifactResults =
                Try.of(() -> aetherRepositorySystem.resolveArtifacts(repositorySession, requestList))
                        .recover(ArtifactResolutionException.class, ArtifactResolutionException::getResults)
                        .get();

        Set<Artifact> result = new HashSet<>();
        artifactResults.forEach(aResult -> {
            if (aResult.isResolved()) {
                result.add(RepositoryUtils.toArtifact(aResult.getArtifact()));
            } else {
                aResult.getExceptions().forEach(
                        e -> LOG.debug("Failed to resolve {}: {}", aResult.getRequest().getArtifact(),
                                e.getMessage()));
            }
        });
        return result;
    }

    /**
     * Resolve all dependencies provided as input. POMs corresponding to the dependencies may optionally be resolved.
     *
     * @param artifacts          Dependencies to be resolved.
     * @param artifactFilter     Skip filter to test against to determine whether dependency must be skipped.
     * @param dependenciesFilter Skip filter to test against to determine whether transitive dependencies must be
     *                           skipped.
     * @param verifyPom          Boolean indicating whether or not POMs corresponding to dependencies should be
     *                           resolved.
     * @param transitive         Boolean indicating whether or not to resolve all dependencies in the transitive closure
     *                           of provided artifact.
     * @return Returns set of resolved artifacts.
     */
    private Set<Artifact> resolveArtifacts(Iterable<Artifact> artifacts, SkipFilter artifactFilter,
                                           SkipFilter dependenciesFilter, boolean verifyPom, boolean transitive)
            throws MojoExecutionException {
        final LinkedHashSet<Artifact> collection = new LinkedHashSet<>();
        for (final Artifact artifact : artifacts) {
            Artifact resolved = resolveArtifact(artifact);
            if (artifactFilter.shouldSkipArtifact(artifact)) {
                LOG.debug("Skipping artifact: {}", artifact);
                continue;
            }
            if (!resolved.isResolved()) {
                throw new MojoExecutionException("Failed to resolve artifact: {}" + artifact);
            }
            collection.add(resolved);
            if (verifyPom) {
                final Artifact resolvedPom = resolvePom(artifact);
                if (resolvedPom.isResolved()) {
                    collection.add(resolvedPom);
                } else {
                    LOG.warn("Failed to resolve pom artifact: {}", resolvedPom);
                }
            }
        }
        if (transitive) {
            // Transitive dependencies are not compiled/tested, so set requirement to scopes relevant at run-time.
            // This is only relevant for plug-in artifacts and their dependencies, as project dependencies are already
            // resolved by Maven.
            // Note: this avoids issues with test-scoped artifacts that are not available to the public, such as
            //       NullAway's test libraries.
            final CompositeSkipper transitivesFilter = new CompositeSkipper(dependenciesFilter,
                    new ScopeSkipper(Artifact.SCOPE_RUNTIME));
            final LinkedHashSet<Artifact> transitives = new LinkedHashSet<>();
            for (Artifact artifact : collection) {
                transitives.addAll(resolveTransitively(artifact, transitivesFilter, verifyPom));
            }
            collection.addAll(transitives);
        }
        return collection;
    }

    private Set<Artifact> resolveTransitively(Artifact artifact, SkipFilter dependencyFilter, boolean verifyPom)
            throws MojoExecutionException {
        final ArtifactFilter requestFilter = a -> !dependencyFilter.shouldSkipArtifact(a);
        final ArtifactResolutionRequest request = new ArtifactResolutionRequest()
                .setArtifact(artifact)
                .setLocalRepository(localRepository)
                .setRemoteRepositories(remoteRepositories)
                .setResolutionFilter(requestFilter)
                .setCollectionFilter(requestFilter)
                .setResolveTransitively(true);
        final ArtifactResolutionResult resolution = repositorySystem.resolve(request);
        if (!resolution.isSuccess()) {
            if (resolution.hasMissingArtifacts()) {
                LOG.warn("Missing artifacts for {}: {}", artifact.getId(), resolution.getMissingArtifacts());
            }
            resolution.getExceptions().forEach(e -> LOG.warn("Failed to resolve transitive dependencies for {}: {}",
                    artifact.getId(), e.getMessage()));
            throw new MojoExecutionException("Failed to resolve transitive dependencies.");
        }
        if (verifyPom) {
            // Verifying project artifacts (POM) is significant as these are used to determine artifact dependencies.
            final LinkedHashSet<Artifact> resolved = new LinkedHashSet<>(resolution.getArtifacts());
            for (Artifact a : resolution.getArtifacts()) {
                resolved.add(resolvePom(a));
            }
            return resolved;
        } else {
            return resolution.getArtifacts();
        }
    }

    public Artifact resolvePom(Artifact artifact) {
        final Artifact pomArtifact = repositorySystem.createProjectArtifact(artifact.getGroupId(),
                artifact.getArtifactId(), artifact.getVersion());
        final ArtifactResolutionResult result = request(pomArtifact, remoteRepositories);
        if (!result.isSuccess()) {
            result.getExceptions().forEach(
                    e -> LOG.debug("Failed to resolve pom {}: {}", pomArtifact.getId(), e.getMessage()));
        }
        return pomArtifact;
    }

    public Artifact resolveArtifact(Artifact artifact) {
        final ArtifactResolutionResult result = request(artifact, remoteRepositories);
        if (!result.isSuccess()) {
            result.getExceptions().forEach(e -> LOG.warn("Failed to resolve {}: {}", artifact.getId(), e.getMessage()));
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
     * Configuration struct for Artifact Resolver.
     */
    public static final class Configuration {

        final SkipFilter dependencyFilter;

        final SkipFilter pluginFilter;

        final boolean verifyPomFiles;

        final boolean verifyPlugins;

        final boolean verifyPluginDependencies;

        final boolean verifyAtypical;

        /**
         * Constructor.
         *
         * @param dependencyFilter         filter for evaluating dependencies
         * @param pluginFilter             filter for evaluating plugins
         * @param verifyPomFiles           verify POM files as well
         * @param verifyPlugins            verify build plugins as well
         * @param verifyPluginDependencies verify all dependencies of build plug-ins.
         * @param verifyAtypical           verify dependencies in a-typical locations, such as maven-compiler-plugin's
         */
        public Configuration(SkipFilter dependencyFilter, SkipFilter pluginFilter, boolean verifyPomFiles,
                             boolean verifyPlugins, boolean verifyPluginDependencies, boolean verifyAtypical) {
            this.dependencyFilter = requireNonNull(dependencyFilter);
            this.pluginFilter = requireNonNull(pluginFilter);
            this.verifyPomFiles = verifyPomFiles;
            this.verifyPlugins = verifyPlugins || verifyPluginDependencies;
            this.verifyPluginDependencies = verifyPluginDependencies;
            this.verifyAtypical = verifyAtypical;
        }
    }
}
