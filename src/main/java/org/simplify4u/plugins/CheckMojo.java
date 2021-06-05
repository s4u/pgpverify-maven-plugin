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
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.inject.Inject;

import io.vavr.control.Try;
import lombok.extern.slf4j.Slf4j;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.ArtifactUtils;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.simplify4u.plugins.keysmap.KeysMap;
import org.simplify4u.plugins.keysmap.KeysMapLocationConfig;
import org.simplify4u.plugins.pgp.PublicKeyUtils;
import org.simplify4u.plugins.pgp.SignatureCheckResult;

/**
 * Check OpenPGP signature of all project and plugins dependencies.
 *
 * @author Slawomir Jaranowski.
 */
@Slf4j
@Mojo(name = CheckMojo.MOJO_NAME, requiresDependencyResolution = ResolutionScope.TEST,
        defaultPhase = LifecyclePhase.VALIDATE, threadSafe = true)
public class CheckMojo extends AbstractVerifyMojo<Boolean> {


    public static final String MOJO_NAME = "check";

    private static final String PGP_VERIFICATION_RESULT_FORMAT = "{} PGP Signature {}\n       {} UserIds: {}";

    @Inject
    protected KeysMap keysMap;

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

    /**
     * check and warn if any of the deprecated options are used.
     */
    @Override
    protected void checkDeprecated() {
        super.checkDeprecated();

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

    @Override
    protected void setupMojo() throws MojoFailureException {
        super.setupMojo();
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

    @Override
    protected void shouldProcess(Set<Artifact> artifacts, Runnable runnable) {

        final File mavenBuildDir = new File(session.getCurrentProject().getBuild().getDirectory());
        final ValidationChecksum validationChecksum = new ValidationChecksum.Builder().destination(mavenBuildDir)
                .artifacts(artifacts).disabled(this.disableChecksum).build();

        if (validationChecksum.checkValidation()) {
            logInfoWithQuiet("Artifacts were already validated in a previous run. "
                    + "Execution finished early as the checksum for the collection of artifacts "
                    + "has not changed.");
        } else {
            runnable.run();
            validationChecksum.saveChecksum();
        }
    }

    @Override
    protected Boolean processArtifactSignature(Artifact artifact, Artifact ascArtifact) {

        SignatureCheckResult signatureCheckResult = signatureUtils.checkSignature(artifact, ascArtifact, pgpKeysCache);
        switch (signatureCheckResult.getStatus()) {
            case ARTIFACT_NOT_RESOLVED:
                throw new PGPMojoException("Artifact not resolved: %s", artifact.getId());
            case ERROR:
                throw new PGPMojoException("Failed to process signature for artifact %s",
                        artifact.getId(), signatureCheckResult.getErrorCause());
            case SIGNATURE_ERROR:
                if (keysMap.isBrokenSignature(artifact)) {
                    logInfoWithQuiet("{} PGP Signature is broken, consistent with keys map.", artifact::getId);
                    return true;
                }

                LOGGER.error("Failed to process signature for artifact {} - {}",
                        artifact.getId(), signatureCheckResult.getErrorMessage());
                return false;
            case SIGNATURE_NOT_RESOLVED:
                return verifySignatureUnavailable(artifact);
            case SIGNATURE_VALID:
                verifyWeakSignature(signatureCheckResult.getSignature().getHashAlgorithm());

                if (!keysMap.isValidKey(artifact, signatureCheckResult.getKey())) {
                    String msg = String.format("%s = %s", ArtifactUtils.key(artifact),
                            PublicKeyUtils.fingerprintForMaster(signatureCheckResult.getKey()));
                    LOGGER.error("Not allowed artifact {} and keyID:\n\t{}\n\t{}",
                            artifact.getId(), msg, signatureCheckResult.getKeyShowUrl());
                    return false;
                }

                LOGGER.debug("signature.KeyAlgorithm: {} signature.hashAlgorithm: {}",
                        signatureCheckResult.getKey().getAlgorithm(),
                        signatureCheckResult.getSignature().getHashAlgorithm());

                logInfoWithQuiet(PGP_VERIFICATION_RESULT_FORMAT, artifact::getId, () -> "OK",
                        () -> PublicKeyUtils.keyIdDescription(signatureCheckResult.getKey()),
                        () -> signatureCheckResult.getKey().getUids());

                return true;
            case SIGNATURE_INVALID:
                if (keysMap.isBrokenSignature(artifact)) {
                    logInfoWithQuiet("{} PGP Signature is broken, consistent with keys map.", artifact::getId);
                    return true;
                }
                if (LOGGER.isErrorEnabled()) {
                    LOGGER.error(PGP_VERIFICATION_RESULT_FORMAT, artifact.getId(),
                            "INVALID", PublicKeyUtils.keyIdDescription(signatureCheckResult.getKey()),
                            signatureCheckResult.getKey().getUids());
                }
                return false;
            case KEY_NOT_FOUND:
                if (keysMap.isKeyMissing(artifact)) {
                    logInfoWithQuiet("{} PGP key not found on keyserver, consistent with keys map.",
                            artifact::getId);
                    return true;
                }

                LOGGER.error("PGP key {} not found on keyserver for artifact {}",
                        signatureCheckResult.getKeyShowUrl(), artifact.getId());
                return false;

            default:
                return false;
        }
    }

    @Override
    protected void processVerificationResult(Set<Boolean> verificationResult) {
        if (verificationResult.stream().anyMatch(result -> !result)) {
            throw new PGPMojoException("Signature errors");
        }
    }


    private void verifyWeakSignature(int hashAlgorithm) {
        final String weakHashAlgorithm = signatureUtils.checkWeakHashAlgorithm(hashAlgorithm);
        if (weakHashAlgorithm == null) {
            return;
        }
        final String logMessage = "Weak signature algorithm used: " + weakHashAlgorithm;
        if (failWeakSignature) {
            LOGGER.error(logMessage);
            throw new PGPMojoException(logMessage);
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
            logInfoWithQuiet("{} PGP Signature unavailable, consistent with keys map.", artifact::getId);
            return true;
        }
        if (keysMap.isWithKey(artifact)) {
            LOGGER.error("Unsigned artifact is listed with key in keys map: {}", artifact.getId());
        } else {
            LOGGER.error("Unsigned artifact not listed in keys map: {}", artifact.getId());
        }
        return false;
    }
}
