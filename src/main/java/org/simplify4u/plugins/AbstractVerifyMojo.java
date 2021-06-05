/*
 * Copyright 2014-2021 Slawomir Jaranowski
 * Portions Copyright 2017-2018 Wren Security.
 * Portions Copyright 2019-2020 Danny van Heumen.
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

import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Parameter;
import org.simplify4u.plugins.ArtifactResolver.Configuration;
import org.simplify4u.plugins.skipfilters.CompositeSkipper;
import org.simplify4u.plugins.skipfilters.ProvidedDependencySkipper;
import org.simplify4u.plugins.skipfilters.ReactorDependencySkipper;
import org.simplify4u.plugins.skipfilters.ScopeSkipper;
import org.simplify4u.plugins.skipfilters.SkipFilter;
import org.simplify4u.plugins.skipfilters.SnapshotDependencySkipper;
import org.simplify4u.plugins.skipfilters.SystemDependencySkipper;

/**
 * Collects project and plugins dependencies and call verification for all artifacts.
 *
 * @param <V> single artifact process result type
 *
 * @author Slawomir Jaranowski.
 */
@Slf4j
public abstract class AbstractVerifyMojo<V> extends AbstractPGPMojo {

    /**
     * Scope used to build dependency list.
     * <p>
     * This scope indicates up to which scope artifacts will be included. For example, the 'test' scope will include
     * <code>provided</code>, <code>compile</code>, <code>runtime</code>, and <code>system</code> scoped dependencies.
     *
     * @since 1.0.0
     */
    @Parameter(property = "pgpverify.scope", defaultValue = "test")
    private String scope;

    /**
     * Verify pom files also.
     *
     * @since 1.1.0
     */
    @Parameter(property = "pgpverify.verifyPomFiles", defaultValue = "true")
    private boolean verifyPomFiles;

    /**
     * Verify dependencies at a SNAPSHOT version, instead of only verifying full release version dependencies.
     *
     * @since 1.2.0
     */
    @Parameter(property = "pgpverify.verifySnapshots", defaultValue = "false")
    private boolean verifySnapshots;

    /**
     * Verify Maven build plug-ins.
     *
     * @since 1.5.0
     */
    @Parameter(property = "pgpverify.verifyPlugins", defaultValue = "false")
    private boolean verifyPlugins;

    /**
     * Verify transitive dependencies of build plug-ins.
     *
     * <p>When enabled, configuration parameter <code>verifyPlugins</code> is enabled implicitly.</p>
     *
     * @since 1.8.0
     */
    @Parameter(property = "pgpverify.verifyPluginDependencies", defaultValue = "false")
    private boolean verifyPluginDependencies;

    /**
     * Verify dependency artifact in atypical locations:
     * <ul>
     *     <li>annotation processors in org.apache.maven.plugins:maven-compiler-plugin configuration.</li>
     * </ul>
     * <p>
     * In addition, it will detect when maven-surefire-plugin version 3 is used, as this will dynamically
     * resolve and load additional artifacts. However, these artifacts are not validated.
     *
     * @since 1.6.0
     */
    @Parameter(property = "pgpverify.verifyAtypical", defaultValue = "false")
    private boolean verifyAtypical;

    /**
     * Verify "provided" dependencies, which the JDK or a container provide at runtime.
     *
     * @since 1.2.0
     */
    @Parameter(property = "pgpverify.verifyProvidedDependencies", defaultValue = "false")
    private boolean verifyProvidedDependencies;

    /**
     * Verify "system" dependencies, which are artifacts that have an explicit path specified in the POM, are always
     * available, and are not looked up in a repository.
     *
     * @since 1.2.0
     */
    @Parameter(property = "pgpverify.verifySystemDependencies", defaultValue = "false")
    private boolean verifySystemDependencies;

    /**
     * Verify dependencies that are part of the current build (what Maven calls the "reactor").
     *
     * <p>This setting only affects multi-module builds that have inter-dependencies between
     * modules. It has no effect on single-module projects nor on multi-module projects that do not have dependencies
     * among the modules.
     *
     * <p>In affected builds, if this setting is {@code true}, and the current build is not applying
     * GPG signatures, then the output artifacts of some of the modules in the build will not be signed. Consequently,
     * other modules within the build that depend on those output artifacts will not pass the GPG signature check
     * because they are unsigned. When this setting is {@code false}, GPG signatures are not checked on output artifacts
     * of modules in the current build, to avoid this issue.
     *
     * @since 1.3.0
     */
    @Parameter(property = "pgpverify.verifyReactorDependencies", defaultValue = "false")
    private boolean verifyReactorDependencies;

    @Override
    public final void executeConfiguredMojo() throws MojoExecutionException {

        final SkipFilter dependencyFilter = prepareDependencyFilters();
        final SkipFilter pluginFilter = preparePluginFilters();

        final long artifactResolutionStart = System.nanoTime();
        final Configuration config = new Configuration(dependencyFilter, pluginFilter, this.verifyPomFiles,
                this.verifyPlugins, this.verifyPluginDependencies, this.verifyAtypical);
        final Set<Artifact> artifacts = artifactResolver.resolveProjectArtifacts(session.getCurrentProject(), config);

        LOGGER.info("Resolved {} artifact(s) in {}", artifacts.size(),
                Duration.ofNanos(System.nanoTime() - artifactResolutionStart));

        shouldProcess(artifacts, () -> {

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Discovered project artifacts: {}", artifacts);
            }

            final long signatureResolutionStart = System.nanoTime();
            final Map<Artifact, Artifact> artifactMap = artifactResolver.resolveSignatures(artifacts);

            LOGGER.info("Resolved {} signature(s) in {}", artifactMap.size(),
                    Duration.ofNanos(System.nanoTime() - signatureResolutionStart));

            Set<V> verificationResult;
            final long artifactValidationStart = System.nanoTime();
            try {
                verificationResult = processArtifactsSignatures(artifactMap);
            } finally {
                LOGGER.info("Finished {} artifact(s) validation in {}", artifactMap.size(),
                        Duration.ofNanos(System.nanoTime() - artifactValidationStart));
            }

            processVerificationResult(verificationResult);
        });
    }

    /**
     * If verification of artifact should be processed, implementet methot must call {@link Runnable#run()}
     *
     * @param artifacts resolved project artifacts
     * @param runnable  lambda to call
     */
    protected abstract void shouldProcess(Set<Artifact> artifacts, Runnable runnable);

    /**
     * Process signature for specific artifact
     *
     * @param artifact    an artifact to check
     * @param ascArtifact an artifact signature
     *
     * @return verification result
     */
    protected abstract V processArtifactSignature(Artifact artifact, Artifact ascArtifact);

    /**
     * Process result of verification all artifacts.
     *
     * @param verificationResult a verification result
     */
    protected abstract void processVerificationResult(Set<V> verificationResult);

    private SkipFilter prepareDependencyFilters() {
        final List<SkipFilter> filters = new LinkedList<>();

        filters.add(new ScopeSkipper(this.scope));

        if (!this.verifySnapshots) {
            filters.add(new SnapshotDependencySkipper());
        }

        if (!this.verifyProvidedDependencies) {
            filters.add(new ProvidedDependencySkipper());
        }

        if (!this.verifySystemDependencies) {
            filters.add(new SystemDependencySkipper());
        }

        if (!this.verifyReactorDependencies) {
            filters.add(new ReactorDependencySkipper(this.session));
        }

        return new CompositeSkipper(filters);
    }

    private SkipFilter preparePluginFilters() {
        final List<SkipFilter> filters = new LinkedList<>();

        if (!this.verifySnapshots) {
            filters.add(new SnapshotDependencySkipper());
        }

        return new CompositeSkipper(filters);
    }

    private Set<V> processArtifactsSignatures(Map<Artifact, Artifact> artifactToAsc) {
        return artifactToAsc.entrySet().stream()
                .map(entry -> processArtifactSignature(entry.getKey(), entry.getValue()))
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }
}
