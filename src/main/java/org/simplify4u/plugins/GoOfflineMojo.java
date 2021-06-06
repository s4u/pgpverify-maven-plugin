/*
 * Copyright 2021 Slawomir Jaranowski
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

import java.util.Collection;
import java.util.Optional;
import java.util.Set;

import lombok.extern.slf4j.Slf4j;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.simplify4u.plugins.pgp.SignatureCheckResult;
import org.simplify4u.plugins.pgp.SignatureStatus;

/**
 * Resolve OpenPGP signature and keys of all project and plugins dependencies.
 * <p>
 * Verification of signature in this goal will not occurs. In case of any problem only warn will be reported.
 *
 * @author Slawomir Jaranowski
 * @since 1.13.0
 */
@Slf4j
@Mojo(name = GoOfflineMojo.MOJO_NAME, requiresDependencyResolution = ResolutionScope.TEST, threadSafe = true)
public class GoOfflineMojo extends AbstractVerifyMojo<Void> {

    public static final String MOJO_NAME = "go-offline";

    @Override
    protected String getMojoName() {
        return MOJO_NAME;
    }

    @Override
    protected void shouldProcess(Set<Artifact> artifacts, Runnable runnable) {
        runnable.run();
    }

    @Override
    protected Void processArtifactSignature(Artifact artifact, Artifact ascArtifact) {
        SignatureCheckResult checkResult = signatureUtils.resolveSignature(artifact, ascArtifact, pgpKeysCache);
        if (checkResult.getStatus() != SignatureStatus.RESOLVED) {
            logWarnWithQuiet("Resolve signature and key for: {} - {} {}",
                    artifact::getId,
                    checkResult::getStatus,
                    () -> Optional.ofNullable(checkResult.getErrorMessage()).orElse(""));
        }
        return null;
    }

    @Override
    protected void processVerificationResult(Collection<Void> verificationResult) {
        // not used
    }
}
