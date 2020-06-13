/*
 * Copyright 2017 Slawomir Jaranowski
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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import io.vavr.control.Try;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.ArtifactUtils;
import org.apache.maven.artifact.repository.ArtifactRepository;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.apache.maven.repository.RepositorySystem;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Settings;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.simplify4u.plugins.ArtifactResolver.Configuration;
import org.simplify4u.plugins.ArtifactResolver.SignatureRequirement;
import org.simplify4u.plugins.keyserver.PGPKeyNotFound;
import org.simplify4u.plugins.keyserver.PGPKeysCache;
import org.simplify4u.plugins.keysmap.KeysMap;
import org.simplify4u.plugins.skipfilters.CompositeSkipper;
import org.simplify4u.plugins.skipfilters.ProvidedDependencySkipper;
import org.simplify4u.plugins.skipfilters.ReactorDependencySkipper;
import org.simplify4u.plugins.skipfilters.ScopeSkipper;
import org.simplify4u.plugins.skipfilters.SkipFilter;
import org.simplify4u.plugins.skipfilters.SnapshotDependencySkipper;
import org.simplify4u.plugins.skipfilters.SystemDependencySkipper;
import org.simplify4u.plugins.utils.PGPSignatureException;
import org.simplify4u.plugins.utils.PGPSignatureUtils;
import org.simplify4u.plugins.utils.PublicKeyUtils;

/**
 * Check PGP signature of dependency.
 *
 * @author Slawomir Jaranowski.
 */
@Mojo(name = "check", requiresProject = true, requiresDependencyResolution = ResolutionScope.TEST,
        defaultPhase = LifecyclePhase.VALIDATE, threadSafe = true)
public class PGPVerifyMojo extends AbstractMojo {

    private static final String PGP_VERIFICATION_RESULT_FORMAT = "%s PGP Signature %s\n       %s UserIds: %s";

    private static final Pattern KEY_SERVERS_SPLIT_PATTERN = Pattern.compile("[;,\\s]");

    @Parameter(property = "project", readonly = true, required = true)
    private MavenProject project;

    @Parameter(defaultValue = "${session}", readonly = true)
    private MavenSession session;

    /**
     * Choose which proxy to use (id from settings.xml in maven config). Uses no proxy if the proxy was not found.
     * If it is not set, it will take the first active proxy if any or no proxy, if no active proxy was found)
     *
     * @since 1.8.0
     */
    @Parameter(property = "pgpverify.proxyName")
    private String proxyName;

    @Parameter(defaultValue = "${settings}", readonly = true)
    private Settings settings;

    @Component
    private RepositorySystem repositorySystem;

    @Component
    private KeysMap keysMap;

    @Parameter(defaultValue = "${localRepository}", readonly = true, required = true)
    private ArtifactRepository localRepository;

    @Parameter(defaultValue = "${project.remoteArtifactRepositories}", readonly = true, required = true)
    private List<ArtifactRepository> remoteRepositories;

    /**
     * The directory for storing cached PGP public keys.
     *
     * @since 1.0.0
     */
    @Parameter(property = "pgpverify.keycache", defaultValue = "${settings.localRepository}/pgpkeys-cache",
            required = true)
    private File pgpKeysCachePath;

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
     * PGP public key servers address.
     *
     * <p>
     * From version <b>1.7.0</b> you can provide many kay servers separated by comma, semicolon or whitespace.
     *
     * @since 1.0.0
     */
    @Parameter(property = "pgpverify.keyserver", defaultValue = "hkps://hkps.pool.sks-keyservers.net", required = true)
    private String pgpKeyServer;

    /**
     * If many key server is provided, use all of them.
     * <p>
     * If set to false only first key server will be used, another as fallback.
     *
     * @since 1.7.0
     */
    @Parameter(property = "pgpverify.keyserversLoadBalance", defaultValue = "true")
    private boolean pgpKeyServerLoadBalance;

    /**
     * Fail the build if any dependency doesn't have a signature.
     *
     * @since 1.1.0
     */
    @Parameter(property = "pgpverify.failNoSignature", defaultValue = "false")
    private boolean failNoSignature;

    /**
     * Fail the build if any artifact without key is not present in the keys map.
     * <p>
     * When enabled, PGPVerify will look up all artifacts in the <code>keys
     * map</code>. Unsigned artifacts will need to be present in the keys map
     * but are expected to have no public key, i.e. an empty string.
     * <p>
     * When <code>strictNoSignature</code> is enabled, PGPVerify will no longer
     * output warnings when unsigned artifacts are encountered. Instead, it will
     * check if the unsigned artifact is listed in the <code>keys map</code>. If
     * so it will proceed, if not it will fail the build.
     *
     * @since 1.5.0
     */
    @Parameter(property = "pgpverify.strictNoSignature", defaultValue = "false")
    private boolean strictNoSignature;

    /**
     * Fail the build if any dependency has a weak signature.
     *
     * @since 1.2.0
     */
    @Parameter(property = "pgpgverify.failWeakSignature", defaultValue = "false")
    private boolean failWeakSignature;

    /**
     * Verify pom files also.
     *
     * @since 1.1.0
     */
    @Parameter(property = "pgpverify.verifyPomFiles", defaultValue = "true")
    private boolean verifyPomFiles;

    /**
     * Verify dependencies at a SNAPSHOT version, instead of only verifying full release version
     * dependencies.
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
     * @since 1.8.0
     */
    @Parameter(property = "pgpverify.verifyPluginDependencies", defaultValue = "false")
    private boolean verifyPluginDependencies;

    /**
     * Verify dependency artifact in atypical locations:
     * <ul>
     *     <li>annotation processors in org.apache.maven.plugins:maven-compiler-plugin configuration.</li>
     * </ul>
     *
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
     * Verify "system" dependencies, which are artifacts that have an explicit path specified in the
     * POM, are always available, and are not looked up in a repository.
     *
     * @since 1.2.0
     */
    @Parameter(property = "pgpverify.verifySystemDependencies", defaultValue = "false")
    private boolean verifySystemDependencies;

    /**
     * Verify dependencies that are part of the current build (what Maven calls the "reactor").
     *
     * <p>This setting only affects multi-module builds that have inter-dependencies between
     * modules. It has no effect on single-module projects nor on multi-module projects that do not
     * have dependencies among the modules.
     *
     * <p>In affected builds, if this setting is {@code true}, and the current build is not applying
     * GPG signatures, then the output artifacts of some of the modules in the build will not be
     * signed. Consequently, other modules within the build that depend on those output artifacts
     * will not pass the GPG signature check because they are unsigned. When this setting is
     * {@code false}, GPG signatures are not checked on output artifacts of modules in the current
     * build, to avoid this issue.
     *
     * @since 1.3.0
     */
    @Parameter(property = "pgpverify.verifyReactorDependencies", defaultValue = "false")
    private boolean verifyReactorDependencies;

    /**
     * Disable the use of a checksum to check whether the collection of artifacts was validated
     * in a previous run. If enabled and the checksum matches, skip subsequent steps that perform
     * actual downloading of signatures and validation of artifacts against their respective
     * signatures.
     *
     * <p>Checksums save significant time when repeatedly checking large artifact collections.</p>
     *
     * @since 1.9.0
     */
    @Parameter(property = "pgpverify.disableChecksum", defaultValue = "false")
    private boolean disableChecksum;

    /**
     * <p>
     * Specifies the location of a file that contains the map of dependencies to PGP key.
     * </p>
     *
     * <p>
     * <a href="keysmap-format.html">Format description.</a>
     * </p>
     *
     * <p>
     * You can use ready keys map: <a href="https://github.com/s4u/pgp-keys-map">https://github.com/s4u/pgp-keys-map</a>
     * </p>
     *
     * @since 1.1.0
     */
    @Parameter(property = "pgpverify.keysMapLocation", defaultValue = "")
    private String keysMapLocation;

    /**
     * Skip verification altogether.
     *
     * @since 1.3.0
     */
    @Parameter(property = "pgpverify.skip", defaultValue = "false")
    private boolean skip;

    /**
     * Only log errors.
     *
     * @since 1.4.0
     */
    @Parameter(property = "pgpverify.quiet", defaultValue = "false")
    private boolean quiet;

    private PGPKeysCache pgpKeysCache;

    private Consumer<Supplier<String>> logWithQuiet;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("Skipping pgpverify:check");
        } else {
            prepareLogWithQuiet();

            final File mavenBuildDir = new File(session.getCurrentProject().getBuild().getDirectory());
            final SkipFilter dependencyFilter = prepareDependencyFilters();
            final SkipFilter pluginFilter = preparePluginFilters();
            prepareForKeys();

            final long artifactResolutionStart = System.nanoTime();
            final ArtifactResolver resolver = new ArtifactResolver(getLog(), repositorySystem, localRepository,
                    remoteRepositories);
            final Configuration config = new Configuration(dependencyFilter, pluginFilter, this.verifyPomFiles,
                    this.verifyPlugins, this.verifyPluginDependencies, this.verifyAtypical);
            final Set<Artifact> artifacts = resolver.resolveProjectArtifacts(this.project, config);

            getLog().info(String.format("Resolved %d artifact(s) in %s", artifacts.size(),
                            Duration.ofNanos(System.nanoTime() - artifactResolutionStart)));

            final ValidationChecksum validationChecksum = new ValidationChecksum.Builder().destination(mavenBuildDir)
                    .artifacts(artifacts).disabled(this.disableChecksum).build();
            if (validationChecksum.checkValidation()) {
                logWithQuiet.accept(() -> "Artifacts were already validated in a previous run. "
                        + "Execution finished early as the checksum for the collection of artifacts "
                        + "has not changed.");
                return;
            }

            if (getLog().isDebugEnabled()) {
                getLog().debug("Discovered project artifacts: " + artifacts);
            }

            final long signatureResolutionStart = System.nanoTime();
            final SignatureRequirement signaturePolicy = determineSignaturePolicy();
            final Map<Artifact, Artifact> artifactMap = resolver.resolveSignatures(artifacts, signaturePolicy);

            getLog().info(String.format("Resolved %d signature(s) in %s", artifactMap.size(),
                            Duration.ofNanos(System.nanoTime() - signatureResolutionStart)));

            final long artifactValidationStart = System.nanoTime();
            try {
                verifyArtifactSignatures(artifactMap);
            } finally {
                getLog().info(String.format("Finished %d artifact(s) validation in %s", artifactMap.size(),
                        Duration.ofNanos(System.nanoTime() - artifactValidationStart)));
            }

            validationChecksum.saveChecksum();
        }
    }

    private void prepareLogWithQuiet() {
        if (quiet) {
            logWithQuiet = message -> {
                if (getLog().isDebugEnabled()) {
                    getLog().debug(message.get());
                }
            };
        } else {
            logWithQuiet = message -> getLog().info(message.get());
        }
    }

    private SignatureRequirement determineSignaturePolicy() {
        if (failNoSignature) {
            return SignatureRequirement.REQUIRED;
        }
        if (strictNoSignature) {
            return SignatureRequirement.STRICT;
        }
        return SignatureRequirement.NONE;
    }

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
            filters.add(new ReactorDependencySkipper(this.project, this.session));
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

    /**
     * Prepare cache and keys map.
     *
     * @throws MojoFailureException
     *         In case of failures during initialization of the PGP keys cache.
     */
    private void prepareForKeys() throws MojoFailureException {
        initCache();

        Try.run(() -> keysMap.load(getLog(), keysMapLocation))
                .getOrElseThrow(e -> new MojoFailureException("load keys map", e));
    }

    private void initCache() throws MojoFailureException {

        List<String> keyServerList = Arrays.stream(KEY_SERVERS_SPLIT_PATTERN.split(pgpKeyServer))
                .map(String::trim)
                .filter(s -> s.length() > 0)
                .collect(Collectors.toList());

        pgpKeysCache = Try.of(() ->
                new PGPKeysCache(pgpKeysCachePath, keyServerList, pgpKeyServerLoadBalance, getMavenProxy()))
                .getOrElseThrow(e -> new MojoFailureException(e.getMessage(), e));
    }

    private void verifyArtifactSignatures(Map<Artifact, Artifact> artifactToAsc)
            throws MojoFailureException, MojoExecutionException {
        boolean isAllSigOk = true;

        for (Map.Entry<Artifact, Artifact> artifactEntry : artifactToAsc.entrySet()) {
            final Artifact artifact = artifactEntry.getKey();
            final Artifact ascArtifact = artifactEntry.getValue();
            final boolean isLastOk = verifyPGPSignature(artifact, ascArtifact);

            isAllSigOk = isAllSigOk && isLastOk;
        }

        if (!isAllSigOk) {
            throw new MojoExecutionException("PGP signature error");
        }
    }

    private boolean verifyPGPSignature(Artifact artifact, Artifact ascArtifact) throws MojoFailureException {
        if (ascArtifact == null) {
            return verifySignatureUnavailable(artifact);
        }
        final File artifactFile = artifact.getFile();
        final File signatureFile = ascArtifact.getFile();

        getLog().debug("Artifact file: " + artifactFile);
        getLog().debug("Artifact sign: " + signatureFile);

        long sigKeyID = -1;
        try {
            final PGPSignature pgpSignature;
            try (FileInputStream input = new FileInputStream(signatureFile)) {
                pgpSignature = PGPSignatureUtils.loadSignature(input);
            }

            verifyWeakSignature(pgpSignature);
            sigKeyID = pgpSignature.getKeyID();

            PGPPublicKeyRing publicKeyRing = pgpKeysCache.getKeyRing(sigKeyID);
            PGPPublicKey publicKey = publicKeyRing.getPublicKey(sigKeyID);

            if (!keysMap.isValidKey(artifact, publicKey, publicKeyRing)) {
                String msg = String.format("%s = %s", ArtifactUtils.key(artifact),
                        PublicKeyUtils.fingerprintForMaster(publicKey, publicKeyRing));
                String keyUrl = pgpKeysCache.getUrlForShowKey(publicKey.getKeyID());
                getLog().error(String.format("Not allowed artifact %s and keyID:%n\t%s%n\t%s",
                        artifact.getId(), msg, keyUrl));
                return false;
            }

            pgpSignature.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
            PGPSignatureUtils.readFileContentInto(pgpSignature, artifactFile);

            getLog().debug("signature.KeyAlgorithm: " + pgpSignature.getKeyAlgorithm()
                    + " signature.hashAlgorithm: " + pgpSignature.getHashAlgorithm());

            return verifySignatureStatus(pgpSignature.verify(), artifact, publicKey, publicKeyRing);
        } catch (PGPKeyNotFound e) {
            if (keysMap.isKeyMissing(artifact)) {
                logWithQuiet.accept(() ->
                        String.format("%s PGP key not found on keyserver, consistent with keys map.",
                                artifact.getId()));
                return true;
            }
            getLog().error(String.format("PGP key %s not found on keyserver for artifact %s",
                    pgpKeysCache.getUrlForShowKey(sigKeyID), artifact.getId()));
            return false;
        } catch (PGPSignatureException e) {
            if (keysMap.isBrokenSignature(artifact)) {
                logWithQuiet.accept(() ->
                        String.format("%s PGP Signature is broken, consistent with keys map.", artifact.getId()));
                return true;
            }

            getLog().error(String.format("Failed to process signature '%s' for artifact %s - %s",
                    signatureFile ,artifact.getId(), e.getMessage()));
            return false;

        } catch (IOException | PGPException  e) {
            throw new MojoFailureException("Failed to process signature '" + signatureFile + "' for artifact "
                    + artifact.getId(), e);
        }
    }

    private void verifyWeakSignature(PGPSignature pgpSignature) throws MojoFailureException {
        final String weakHashAlgorithm = PGPSignatureUtils.checkWeakHashAlgorithm(pgpSignature);
        if (weakHashAlgorithm == null) {
            return;
        }
        final String logMessage = "Weak signature algorithm used: " + weakHashAlgorithm;
        if (failWeakSignature) {
            getLog().error(logMessage);
            throw new MojoFailureException(logMessage);
        } else {
            getLog().warn(logMessage);
        }
    }

    /**
     * Verify if unsigned artifact is correctly listed in keys map.
     *
     * @param artifact
     *         the artifact which is supposedly unsigned
     *
     * @return Returns <code>true</code> if correctly missing according to keys map,
     * or <code>false</code> if verification fails.
     */
    private boolean verifySignatureUnavailable(Artifact artifact) {
        if (keysMap.isNoSignature(artifact)) {
            logWithQuiet.accept(() ->
                    String.format("%s PGP Signature unavailable, consistent with keys map.", artifact.getId()));
            return true;
        }
        if (keysMap.isWithKey(artifact)) {
            getLog().error("Unsigned artifact is listed with key in keys map: " + artifact.getId());
        } else {
            getLog().error("Unsigned artifact not listed in keys map: " + artifact.getId());
        }
        return false;
    }

    /**
     * Returns the maven proxy with a matching id or the first active one
     *
     * @return the maven proxy
     */
    Proxy getMavenProxy() {
        if (settings != null) {
            List<Proxy> proxies = settings.getProxies();
            if (proxies != null && !proxies.isEmpty()) {
                if (proxyName != null) {
                    return proxies.stream().filter(proxy -> proxyName.equalsIgnoreCase(proxy.getId())).findFirst()
                               .orElse(null);
                } else {
                    return proxies.stream().filter(Proxy::isActive).findFirst().orElse(null);
                }
            }
        }
        return null;
    }

    private boolean verifySignatureStatus(boolean signatureStatus, Artifact artifact,
                                          PGPPublicKey publicKey, PGPPublicKeyRing publicKeyRing) {

        if (signatureStatus) {
            logWithQuiet.accept(() -> String.format(PGP_VERIFICATION_RESULT_FORMAT, artifact.getId(),
                    "OK", PublicKeyUtils.keyIdDescription(publicKey, publicKeyRing),
                    PublicKeyUtils.getUserIDs(publicKey, publicKeyRing)));
            return true;
        } else {
            if (keysMap.isBrokenSignature(artifact)) {
                logWithQuiet.accept(() ->
                        String.format("%s PGP Signature is broken, consistent with keys map.", artifact.getId()));
                return true;
            } else {
                getLog().error(String.format(PGP_VERIFICATION_RESULT_FORMAT, artifact.getId(),
                        "INVALID", PublicKeyUtils.keyIdDescription(publicKey, publicKeyRing),
                        PublicKeyUtils.getUserIDs(publicKey, publicKeyRing)));
                return false;
            }
        }
    }
}
