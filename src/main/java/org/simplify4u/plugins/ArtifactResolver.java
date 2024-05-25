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
import java.util.stream.Stream;

import io.vavr.control.Try;
import org.apache.maven.RepositoryUtils;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.versioning.DefaultArtifactVersion;
import org.apache.maven.artifact.versioning.VersionRange;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.ModelBase;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.ReportPlugin;
import org.apache.maven.model.Reporting;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.RequestTrace;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.collection.CollectRequest;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.repository.RepositoryPolicy;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.ArtifactResult;
import org.eclipse.aether.resolution.DependencyRequest;
import org.eclipse.aether.resolution.DependencyResolutionException;
import org.eclipse.aether.resolution.DependencyResult;
import org.eclipse.aether.util.artifact.SubArtifact;
import org.simplify4u.plugins.skipfilters.SkipFilter;
import org.simplify4u.plugins.utils.MavenCompilerUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private final RepositorySystemSession repositorySession;

    private final List<RemoteRepository> remoteProjectRepositories;

    private final List<RemoteRepository> remotePluginRepositories;

    /**
     * Copy of remote repositories with check sum policy set to ignore, we need it for pgp signature resolving.
     * <p>
     * pgp signature *.asc is signature so there is'n signature for signature
     */
    private final List<RemoteRepository> remoteRepositoriesIgnoreCheckSum;

    @Inject
    ArtifactResolver(MavenSession session, RepositorySystem repositorySystem) {
        this.remoteProjectRepositories = requireNonNull(session.getCurrentProject().getRemoteProjectRepositories());
        this.remotePluginRepositories = requireNonNull(session.getCurrentProject().getRemotePluginRepositories());
        this.repositorySystem = requireNonNull(repositorySystem);
        this.repositorySession = requireNonNull(session.getRepositorySession());
        this.remoteRepositoriesIgnoreCheckSum = repositoriesIgnoreCheckSum(remoteProjectRepositories,
                remotePluginRepositories);
    }

    /**
     * Wrap remote repository with ignore check sum policy.
     *
     * @param remoteProjectRepositories project repositories to wrap
     * @param remotePluginRepositories  plugin repositories to wrap
     * @return wrapped repository list
     */
    private List<RemoteRepository> repositoriesIgnoreCheckSum(List<RemoteRepository> remoteProjectRepositories,
                                                                     List<RemoteRepository> remotePluginRepositories) {

        Stream<RemoteRepository> remoteProjectRepositoryStream = Optional.ofNullable(remoteProjectRepositories)
                .orElse(Collections.emptyList())
                .stream();

        Stream<RemoteRepository> remotePluginsRepositoryStream = Optional.ofNullable(remotePluginRepositories)
                .orElse(Collections.emptyList())
                .stream();

        List<RemoteRepository> remoteRepositories =
                Stream.concat(remoteProjectRepositoryStream, remotePluginsRepositoryStream)
                        .map(ArtifactResolver::repositoryIgnoreCheckSum)
                        .collect(Collectors.toList());

        return repositorySystem.newResolutionRepositories(repositorySession, remoteRepositories);
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
    Set<Artifact> resolveProjectArtifacts(MavenProject project, Configuration config) {

        final LinkedHashSet<Artifact> allArtifacts = new LinkedHashSet<>(resolveProjectArtifacts(project.getArtifacts(),
                config.dependencyFilter, config.verifyPomFiles));

        if (config.verifyPlugins) {
            // Resolve transitive dependencies for build plug-ins and reporting plug-ins and their dependencies.
            // The transitive closure is computed for each plug-in with its dependencies, as individual executions may
            // depend on a different version of a particular dependency. Therefore, a dependency may be included in the
            // over-all artifacts list multiple times with different versions.
            for (final Plugin plugin : project.getBuildPlugins()) {
                List<Artifact> resolved = resolvePlugin(plugin, config);
                allArtifacts.addAll(resolved);
            }

            List<ReportPlugin> reportPlugins = Optional.ofNullable(project.getModel())
                    .map(ModelBase::getReporting)
                    .map(Reporting::getPlugins)
                    .orElseGet(Collections::emptyList);

            for (ReportPlugin plugin : reportPlugins) {
                Plugin p = new Plugin();
                p.setGroupId(plugin.getGroupId());
                p.setArtifactId(plugin.getArtifactId());
                p.setVersion(plugin.getVersion());
                List<Artifact> resolved = resolvePlugin(p, config);
                allArtifacts.addAll(resolved);
            }
        }
        if (config.verifyAtypical) {
            // Verify artifacts in atypical locations, such as references in configuration.
            List<org.eclipse.aether.artifact.Artifact> artifacts = searchCompilerAnnotationProcessors(project);

            artifacts.forEach(a -> {
                Plugin p = new Plugin();
                p.setGroupId(a.getGroupId());
                p.setArtifactId(a.getArtifactId());
                p.setVersion(a.getVersion());
                List<Artifact> resolved = resolvePlugin(p, config);
                allArtifacts.addAll(resolved);
            });

            informSurefire3RuntimeDependencyLoadingLimitation(project);
        }
        return allArtifacts;
    }

    private List<Artifact> resolvePlugin(Plugin plugin, Configuration config) {
        org.eclipse.aether.artifact.Artifact pArtifact = toArtifact(plugin);

        if (config.pluginFilter.shouldSkipArtifact(RepositoryUtils.toArtifact(pArtifact))) {
            return Collections.emptyList();
        }

        List<org.eclipse.aether.artifact.Artifact> result;
        if (config.verifyPluginDependencies) {
            // we need resolve all transitive dependencies
            result = resolvePluginArtifactsTransitive(pArtifact, plugin.getDependencies(), config.verifyPomFiles);
        } else {
            // only resolve plugin artifact
            List<org.eclipse.aether.artifact.Artifact> aeArtifacts = new ArrayList<>();
            aeArtifacts.add(pArtifact);
            aeArtifacts.addAll(plugin.getDependencies().stream().map(
                            d -> RepositoryUtils.toDependency(d, repositorySession.getArtifactTypeRegistry()))
                    .map(Dependency::getArtifact)
                    .collect(Collectors.toList()));

            result = resolveArtifacts(aeArtifacts, remotePluginRepositories, config.verifyPomFiles);
        }

        return result.stream().map(RepositoryUtils::toArtifact).collect(Collectors.toList());
    }

    private List<org.eclipse.aether.artifact.Artifact> resolvePluginArtifactsTransitive(
            org.eclipse.aether.artifact.Artifact artifact,
            List<org.apache.maven.model.Dependency> dependencies, boolean verifyPomFiles) {

        CollectRequest collectRequest = new CollectRequest(new Dependency(artifact, "runtime"),
                remotePluginRepositories);

        dependencies.stream().map(d -> RepositoryUtils.toDependency(d, repositorySession.getArtifactTypeRegistry()))
                .forEach(collectRequest::addDependency);

        DependencyRequest request = new DependencyRequest(collectRequest, null);

        DependencyResult dependencyResult =
                Try.of(() -> repositorySystem.resolveDependencies(repositorySession, request))
                        .recover(DependencyResolutionException.class, DependencyResolutionException::getResult)
                        .get();

        List<org.eclipse.aether.artifact.Artifact> result = new ArrayList<>(
                dependencyResult.getArtifactResults().stream()
                        .map(aResult -> aResult.isResolved() ?
                                aResult.getArtifact() :
                                aResult.getRequest().getArtifact())
                        .collect(Collectors.toList()));

        if (verifyPomFiles) {
            resolvePoms(result, remotePluginRepositories);
        }
        return result;
    }

    private List<org.eclipse.aether.artifact.Artifact> resolveArtifacts(
            List<org.eclipse.aether.artifact.Artifact> artifacts,
            List<RemoteRepository> remoteRepositories,
            boolean verifyPomFiles) {

        List<ArtifactRequest> requestList = artifacts.stream()
                .map(a -> new ArtifactRequest(a, remoteRepositories, null))
                .collect(Collectors.toList());

        List<org.eclipse.aether.artifact.Artifact> result =
                new ArrayList<>(Try.of(() -> repositorySystem.resolveArtifacts(repositorySession, requestList))
                        .recover(ArtifactResolutionException.class, ArtifactResolutionException::getResults)
                        .get()
                        .stream()
                        .map(aResult -> aResult.isResolved() ?
                                aResult.getArtifact() :
                                aResult.getRequest().getArtifact())
                        .collect(Collectors.toList()));

        if (verifyPomFiles) {
            resolvePoms(result, remoteRepositories);
        }

        return result;

    }

    private void resolvePoms(List<org.eclipse.aether.artifact.Artifact> result,
                             List<RemoteRepository> remoteRepositories) {
        List<org.eclipse.aether.artifact.Artifact> poms =
                result.stream().filter(a -> !"pom".equals(a.getExtension()))
                        .map(a -> new SubArtifact(a, null, "pom"))
                        .collect(Collectors.toList());

        result.addAll(resolveArtifacts(poms, remoteRepositories, false));
    }

    private static org.eclipse.aether.artifact.Artifact toArtifact(Plugin plugin) {
        String version = plugin.getVersion();
        if (version == null || version.isEmpty()) {
            version = "RELEASE";
        }
        return new DefaultArtifact(plugin.getGroupId(), plugin.getArtifactId(), "jar", version);
    }

    private static List<org.eclipse.aether.artifact.Artifact> searchCompilerAnnotationProcessors(MavenProject project) {
        return project.getBuildPlugins().stream()
                .filter(MavenCompilerUtils::checkCompilerPlugin)
                .flatMap(p -> extractAnnotationProcessors(p).stream())
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
    private static void informSurefire3RuntimeDependencyLoadingLimitation(MavenProject project) {
        final boolean surefireDynamicLoadingLikely = project.getBuildPlugins().stream()
                .filter(p -> "org.apache.maven.plugins".equals(p.getGroupId()))
                .filter(p -> "maven-surefire-plugin".equals(p.getArtifactId()))
                .anyMatch(ArtifactResolver::matchSurefireVersion);
        if (surefireDynamicLoadingLikely) {
            LOG.info("NOTE: maven-surefire-plugin version 3 is present. This version is known to resolve " +
                    "and load dependencies for various unit testing frameworks (called \"providers\") during " +
                    "execution. These dependencies are not validated.");
        }
    }

    private static boolean matchSurefireVersion(Plugin plugin) {
        return Try.of(() -> new DefaultArtifactVersion(plugin.getVersion()))
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
                Try.of(() -> repositorySystem.resolveArtifacts(repositorySession, requestList))
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
                .map(a -> new ArtifactRequest(a, remoteProjectRepositories, null))
                .collect(Collectors.toList());

        List<ArtifactResult> artifactResults =
                Try.of(() -> repositorySystem.resolveArtifacts(repositorySession, requestList))
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
     * Resolve given artifact.
     *
     * @param artifact       - an artiact to resolve
     * @param verifyPomFiles - if true also pom will be resolved for artifact
     * @return an resolved artifact
     */
    public List<Artifact> resolveArtifact(Artifact artifact, boolean verifyPomFiles) {

        List<org.eclipse.aether.artifact.Artifact> artifacts =
                resolveArtifacts(Collections.singletonList(RepositoryUtils.toArtifact(artifact)),
                        remoteProjectRepositories, verifyPomFiles);

        return artifacts.stream().map(RepositoryUtils::toArtifact).collect(Collectors.toList());
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
