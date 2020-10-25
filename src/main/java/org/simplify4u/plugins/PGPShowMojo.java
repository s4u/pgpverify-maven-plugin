/*
 * Copyright 2020 Slawomir Jaranowski
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

import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.inject.Inject;

import static org.simplify4u.plugins.ArtifactResolver.SignatureRequirement.NONE;

import io.vavr.control.Try;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.repository.RepositorySystem;
import org.apache.maven.shared.utils.logging.MessageBuilder;
import org.apache.maven.shared.utils.logging.MessageUtils;
import org.bouncycastle.openpgp.PGPUtil;
import org.simplify4u.plugins.keyserver.PGPKeysCache;
import org.simplify4u.plugins.pgp.ArtifactInfo;
import org.simplify4u.plugins.pgp.KeyInfo;
import org.simplify4u.plugins.pgp.PGPSignatureInfo;
import org.simplify4u.plugins.pgp.SignatureInfo;
import org.simplify4u.plugins.pgp.SignatureStatus;
import org.simplify4u.plugins.utils.PGPSignatureUtils;

/**
 * Show information about artifact signature.
 *
 * @author Slawomir Jaranowski
 * @since 1.10.0
 */
@Slf4j
@Mojo(name = PGPShowMojo.MOJO_NAME, requiresDirectInvocation = true, requiresOnline = true, requiresProject = false)
public class PGPShowMojo extends AbstractPGPMojo {

    public static final String MOJO_NAME = "show";

    private final RepositorySystem repositorySystem;

    /**
     * Show signature for pom files also.
     *
     * @since 1.10.0
     */
    @Setter
    @Parameter(property = "showPom", defaultValue = "false")
    protected boolean showPom;

    /**
     * A artifact name to show pgp signature in format <code>groupId:artifactId:version[:packaging[:classifier]]</code>.
     *
     * @since 1.10.0
     */
    @Parameter(property = "artifact", required = true)
    @Setter
    private String artifact;

    private boolean hasError;

    @Inject
    PGPShowMojo(ArtifactResolver artifactResolver, PGPKeysCache pgpKeysCache, PGPSignatureUtils pgpSignatureUtils,
            MavenSession session, RepositorySystem repositorySystem) {
        super(artifactResolver, pgpKeysCache, pgpSignatureUtils, session);
        this.repositorySystem = repositorySystem;
    }

    @Override
    protected String getMojoName() {
        return MOJO_NAME;
    }

    @Override
    protected void executeConfiguredMojo() throws MojoExecutionException {


        Set<Artifact> artifactsToCheck = new HashSet<>();
        Artifact artifactToCheck = prepareArtifactToCheck();

        artifactsToCheck.add(artifactResolver.resolveArtifact(artifactToCheck));

        if (showPom && artifactToCheck.isResolved()) {
            artifactsToCheck.add(artifactResolver.resolvePom(artifactToCheck));
        }

        Map<Artifact, Artifact> artifactMap = artifactResolver.resolveSignatures(artifactsToCheck, NONE);

        artifactMap.forEach(this::processArtifact);

        if (hasError) {
            throw new PGPMojoException("Some of artifact can't be checked");
        }
    }

    private void processArtifact(Artifact artifact, Artifact artifactAsc) {

        PGPSignatureInfo signatureInfo = pgpSignatureUtils.getSignatureInfo(artifact, artifactAsc, pgpKeysCache);

        MessageBuilder messageBuilder = MessageUtils.buffer();
        messageBuilder.newline();
        messageBuilder.newline();

        ArtifactInfo artifactInfo = signatureInfo.getArtifact();

        messageBuilder.a("Artifact:").newline();
        messageBuilder.a("\tgroupId:     ").strong(artifactInfo.getGroupId()).newline();
        messageBuilder.a("\tartifactId:  ").strong(artifactInfo.getArtifactId()).newline();
        messageBuilder.a("\ttype:        ").strong(artifactInfo.getType()).newline();
        Optional.ofNullable(artifactInfo.getClassifier()).ifPresent(
                classifier -> messageBuilder.a("\tclassifier:  ").strong(classifier).newline());
        messageBuilder.a("\tversion:     ").strong(artifactInfo.getVersion()).newline();
        if (signatureInfo.getStatus() == SignatureStatus.ARTIFACT_NOT_RESOLVED) {
            messageBuilder.a("\t").error("artifact was not resolved  - try mvn -U ...").newline();
        }

        messageBuilder.newline();

        SignatureInfo signature = signatureInfo.getSignature();
        if (signature != null) {
            messageBuilder.a("PGP signature:").newline();
            messageBuilder.a("\tversion:     ").strong(signature.getVersion()).newline();
            messageBuilder.a("\talgorithm:   ")
                    .strong(Try.of(() ->
                            PGPUtil.getSignatureName(signature.getKeyAlgorithm(), signature.getHashAlgorithm())).get())
                    .newline();
            messageBuilder.a("\tkeyId:       ").strong(signature.getKeyId()).newline();
            messageBuilder.a("\tcreate date: ").strong(signature.getDate()).newline();
            messageBuilder.a("\tstatus:      ");
            if (signatureInfo.getStatus() == SignatureStatus.SIGNATURE_VALID) {
                messageBuilder.success("valid");
            } else {
                messageBuilder.error("invalid");
            }
            messageBuilder.newline();
        } else if (signatureInfo.getStatus() == SignatureStatus.SIGNATURE_NOT_RESOLVED) {
            messageBuilder.a("\t")
                    .error("PGP signature was not resolved - try mvn -U ...").newline();
        }

        messageBuilder.newline();

        KeyInfo key = signatureInfo.getKey();
        if (key != null) {
            messageBuilder.a("PGP key:").newline();
            messageBuilder.a("\tversion:     ").strong(key.getVersion()).newline();
            messageBuilder.a("\talgorithm:   ")
                    .strong(pgpSignatureUtils.keyAlgorithmName(key.getAlgorithm())).newline();
            messageBuilder.a("\tbits:        ").strong(key.getBits()).newline();
            messageBuilder.a("\tfingerprint: ").strong(key.getFingerprint()).newline();
            Optional.ofNullable(key.getMaster()).ifPresent(masterKey ->
                    messageBuilder.a("\tmaster key:  ").strong(masterKey).newline()
            );
            messageBuilder.a("\tcreate date: ").strong(key.getDate()).newline();
            messageBuilder.a("\tuids:        ").strong(key.getUids()).newline();
        }

        messageBuilder.newline();

        Optional.ofNullable(signatureInfo.getErrorMessage()).ifPresent(errorMessage ->
                messageBuilder.error(errorMessage).newline());

        LOGGER.info(messageBuilder.toString());

        hasError |= (signatureInfo.getStatus() != SignatureStatus.SIGNATURE_VALID
                && signatureInfo.getStatus() != SignatureStatus.SIGNATURE_INVALID);
    }

    private Artifact prepareArtifactToCheck() {

        String[] aItems = Optional.ofNullable(artifact).map(String::trim)
                .map(s -> s.split(":"))
                .filter(a -> a.length >= 3 && a.length <= 5)
                .orElseThrow(() ->
                        new PGPMojoException("The parameters 'artifact' is miss or in invalid format"
                                + " - groupId:artifactId:version[:packaging[:classifier]]"));

        return repositorySystem.createArtifactWithClassifier(aItems[0], aItems[1], aItems[2],
                getItem(aItems, 3, "jar"), getItem(aItems, 4, null));
    }

    private static String getItem(String[] items, int index, String defaultValue) {
        if (items.length > index) {
            return items[index];
        }
        return defaultValue;
    }
}
