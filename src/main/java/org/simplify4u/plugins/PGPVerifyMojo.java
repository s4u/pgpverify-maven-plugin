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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.inject.Inject;

import io.vavr.control.Try;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.ArtifactUtils;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.simplify4u.plugins.ArtifactResolver.Configuration;
import org.simplify4u.plugins.keyserver.PGPKeyNotFound;
import org.simplify4u.plugins.keysmap.KeysMap;
import org.simplify4u.plugins.keysmap.KeysMapLocationConfig;
import org.simplify4u.plugins.skipfilters.CompositeSkipper;
import org.simplify4u.plugins.skipfilters.ProvidedDependencySkipper;
import org.simplify4u.plugins.skipfilters.ReactorDependencySkipper;
import org.simplify4u.plugins.skipfilters.ScopeSkipper;
import org.simplify4u.plugins.skipfilters.SkipFilter;
import org.simplify4u.plugins.skipfilters.SnapshotDependencySkipper;
import org.simplify4u.plugins.skipfilters.SystemDependencySkipper;
import org.simplify4u.plugins.utils.PGPKeyId;
import org.simplify4u.plugins.utils.PGPSignatureException;
import org.simplify4u.plugins.utils.PublicKeyUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Check PGP signature of dependency.
 *
 * @author Slawomir Jaranowski.
 */
@Mojo(name = PGPVerifyMojo.MOJO_NAME, requiresProject = true, requiresDependencyResolution = ResolutionScope.TEST,
        defaultPhase = LifecyclePhase.VALIDATE, threadSafe = true)
public class PGPVerifyMojo extends AbstractPGPMojo {

    private static final Logger LOGGER = LoggerFactory.getLogger(PGPVerifyMojo.class);

    public static final String MOJO_NAME = "check";

    private static final String PGP_VERIFICATION_RESULT_FORMAT = "{} PGP Signature {}\n       {} UserIds: {}";

    @Inject
    protected KeysMap keysMap;

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
     * Fail the build if any dependency doesn't have a signature.
     *
     * @since 1.1.0
     * @deprecated Deprecated as of 1.13.0: this requirement can be expressed through the keysMap.
     */
    @Deprecated
    @Parameter(property = "pgpverify.failNoSignature")
    private Boolean failNoSignature;

    /**
     * Does nothing - to be removed.
     *
     * @since 1.5.0
     * @deprecated Deprecated as of 1.9.0: this requirement can be expressed through the keysMap.
     */
    @Deprecated
    @Parameter(property = "pgpverify.strictNoSignature")
    private Boolean strictNoSignature;

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

    /**
     * Disable the use of a checksum to check whether the collection of artifacts was validated in a previous run. If
     * enabled and the checksum matches, skip subsequent steps that perform actual downloading of signatures and
     * validation of artifacts against their respective signatures.
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
     * This can be path to local file, path to file on plugin classpath or url address.
     * </p>
     *
     * <p>
     * <a href="keysmap-format.html">Format description.</a>
     * </p>
     *
     * <p>
     * Since version <b>1.12.0</b> - <a href="keysmap-multiple.html">Multiple KeysMpa configuration</a>
     * </p>
     *
     * <p>
     * You can use ready keys map: <a href="https://github.com/s4u/pgp-keys-map">https://github.com/s4u/pgp-keys-map</a>
     * </p>
     *
     * @since 1.1.0
     */
    @Parameter(property = "pgpverify.keysMapLocation", alias = "keysMapLocations")
    private List<KeysMapLocationConfig> keysMapLocation = new ArrayList<>();

    @Override
    protected String getMojoName() {
        return MOJO_NAME;
    }

    @Override
    public void executeConfiguredMojo() throws MojoExecutionException, MojoFailureException {

        initKeysMap();

        checkDeprecated();

        final File mavenBuildDir = new File(session.getCurrentProject().getBuild().getDirectory());
        final SkipFilter dependencyFilter = prepareDependencyFilters();
        final SkipFilter pluginFilter = preparePluginFilters();

        final long artifactResolutionStart = System.nanoTime();
        final Configuration config = new Configuration(dependencyFilter, pluginFilter, this.verifyPomFiles,
                this.verifyPlugins, this.verifyPluginDependencies, this.verifyAtypical);
        final Set<Artifact> artifacts = artifactResolver.resolveProjectArtifacts(session.getCurrentProject(), config);

        LOGGER.info("Resolved {} artifact(s) in {}", artifacts.size(),
                Duration.ofNanos(System.nanoTime() - artifactResolutionStart));

        final ValidationChecksum validationChecksum = new ValidationChecksum.Builder().destination(mavenBuildDir)
                .artifacts(artifacts).disabled(this.disableChecksum).build();
        if (validationChecksum.checkValidation()) {
            logWithQuiet("Artifacts were already validated in a previous run. "
                    + "Execution finished early as the checksum for the collection of artifacts "
                    + "has not changed.");
            return;
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Discovered project artifacts: {}", artifacts);
        }

        final long signatureResolutionStart = System.nanoTime();
        final Map<Artifact, Artifact> artifactMap = artifactResolver.resolveSignatures(artifacts);

        LOGGER.info("Resolved {} signature(s) in {}", artifactMap.size(),
                Duration.ofNanos(System.nanoTime() - signatureResolutionStart));

        final long artifactValidationStart = System.nanoTime();
        try {
            verifyArtifactSignatures(artifactMap);
        } finally {
            LOGGER.info("Finished {} artifact(s) validation in {}", artifactMap.size(),
                    Duration.ofNanos(System.nanoTime() - artifactValidationStart));
        }

        validationChecksum.saveChecksum();
    }

    /**
     * check and warn if any of the deprecated options are used.
     */
    private void checkDeprecated() {
        if (strictNoSignature != null) {
            LOGGER.warn("strictNoSignature is deprecated - this requirement can be expressed through the keysMap");
        }
        if (failNoSignature != null) {
            LOGGER.warn("failNoSignature is deprecated - this requirement can be expressed through the keysMap");
        }
        if (Boolean.TRUE.equals(failNoSignature) && keysMap.isEmpty()) {
            // for backward compatibility
            LOGGER.warn("failNoSignature is true and keysMap is empty we add `* = any` to keysMap "
                    + "for backward compatibility");
            KeysMapLocationConfig keysMapLocationConfig = new KeysMapLocationConfig();
            keysMapLocationConfig.set("/any-valid-signatures.list");
            Try.run(() -> keysMap.load(keysMapLocationConfig))
                    .getOrElseThrow(e -> new PGPMojoException(e.getMessage(), e));
        }
    }

    private void initKeysMap() {

        LOGGER.debug("keysMapLocation={}", keysMapLocation);

        keysMapLocation.forEach(location ->
                Try.run(() -> keysMap.load(location))
                        .getOrElseThrow(e -> new PGPMojoException(e.getMessage(), e)));

        if (keysMap.isEmpty()) {
            LOGGER.warn("No keysmap specified in configuration or keysmap contains no entries. PGPVerify will only " +
                    "check artifacts against their signature. File corruption will be detected. However, without a " +
                    "keysmap as a reference for trust, valid signatures of any public key will be accepted.");
        }
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

        LOGGER.debug("Artifact file: {}", artifactFile);
        LOGGER.debug("Artifact sign: {}", signatureFile);

        PGPKeyId sigKeyID = null;
        try {
            final PGPSignature pgpSignature;
            try (FileInputStream input = new FileInputStream(signatureFile)) {
                pgpSignature = pgpSignatureUtils.loadSignature(input);
            }

            verifyWeakSignature(pgpSignature);
            sigKeyID = pgpSignatureUtils.retrieveKeyId(pgpSignature);

            PGPPublicKeyRing publicKeyRing = pgpKeysCache.getKeyRing(sigKeyID);
            PGPPublicKey publicKey = sigKeyID.getKeyFromRing(publicKeyRing);

            if (!keysMap.isValidKey(artifact, publicKey, publicKeyRing)) {
                String msg = String.format("%s = %s", ArtifactUtils.key(artifact),
                        PublicKeyUtils.fingerprintForMaster(publicKey, publicKeyRing));
                String keyUrl = pgpKeysCache.getUrlForShowKey(sigKeyID);
                LOGGER.error("Not allowed artifact {} and keyID:\n\t{}\n\t{}",
                        artifact.getId(), msg, keyUrl);
                return false;
            }

            pgpSignature.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
            pgpSignatureUtils.readFileContentInto(pgpSignature, artifactFile);

            LOGGER.debug("signature.KeyAlgorithm: {} signature.hashAlgorithm: {}",
                    pgpSignature.getKeyAlgorithm(), pgpSignature.getHashAlgorithm());

            return verifySignatureStatus(pgpSignature.verify(), artifact, publicKey, publicKeyRing);
        } catch (PGPKeyNotFound e) {
            if (keysMap.isKeyMissing(artifact)) {
                logWithQuiet("{} PGP key not found on keyserver, consistent with keys map.",
                        artifact::getId);
                return true;
            }

            LOGGER.error("PGP key {} not found on keyserver for artifact {}",
                    pgpKeysCache.getUrlForShowKey(sigKeyID), artifact.getId());
            return false;
        } catch (PGPSignatureException e) {
            if (keysMap.isBrokenSignature(artifact)) {
                logWithQuiet("{} PGP Signature is broken, consistent with keys map.", artifact::getId);
                return true;
            }

            LOGGER.error("Failed to process signature '{}' for artifact {} - {}",
                    signatureFile, artifact.getId(), e.getMessage());
            return false;

        } catch (IOException | PGPException e) {
            throw new MojoFailureException("Failed to process signature '" + signatureFile + "' for artifact "
                    + artifact.getId(), e);
        }
    }

    private void verifyWeakSignature(PGPSignature pgpSignature) throws MojoFailureException {
        final String weakHashAlgorithm = pgpSignatureUtils.checkWeakHashAlgorithm(pgpSignature);
        if (weakHashAlgorithm == null) {
            return;
        }
        final String logMessage = "Weak signature algorithm used: " + weakHashAlgorithm;
        if (failWeakSignature) {
            LOGGER.error(logMessage);
            throw new MojoFailureException(logMessage);
        } else {
            LOGGER.warn(logMessage);
        }
    }

    /**
     * Verify if unsigned artifact is correctly listed in keys map.
     *
     * @param artifact the artifact which is supposedly unsigned
     *
     * @return Returns <code>true</code> if correctly missing according to keys map, or <code>false</code> if
     * verification fails.
     */
    private boolean verifySignatureUnavailable(Artifact artifact) {
        if (keysMap.isEmpty()) {
            LOGGER.warn("No signature for {}", artifact.getId());
            return true;
        }
        if (keysMap.isNoSignature(artifact)) {
            logWithQuiet("{} PGP Signature unavailable, consistent with keys map.", artifact::getId);
            return true;
        }
        if (keysMap.isWithKey(artifact)) {
            LOGGER.error("Unsigned artifact is listed with key in keys map: {}", artifact.getId());
        } else {
            LOGGER.error("Unsigned artifact not listed in keys map: {}", artifact.getId());
        }
        return false;
    }

    private boolean verifySignatureStatus(boolean signatureStatus, Artifact artifact,
            PGPPublicKey publicKey, PGPPublicKeyRing publicKeyRing) {

        if (signatureStatus) {
            logWithQuiet(PGP_VERIFICATION_RESULT_FORMAT, artifact::getId, () -> "OK",
                    () -> PublicKeyUtils.keyIdDescription(publicKey, publicKeyRing),
                    () -> PublicKeyUtils.getUserIDs(publicKey, publicKeyRing));
            return true;
        } else if (keysMap.isBrokenSignature(artifact)) {
            logWithQuiet("{} PGP Signature is broken, consistent with keys map.", artifact::getId);
            return true;
        }
        if (LOGGER.isErrorEnabled()) {
            LOGGER.error(PGP_VERIFICATION_RESULT_FORMAT, artifact.getId(),
                    "INVALID", PublicKeyUtils.keyIdDescription(publicKey, publicKeyRing),
                    PublicKeyUtils.getUserIDs(publicKey, publicKeyRing));
        }
        return false;
    }
}
