/*
 * Copyright 2020-2021 Slawomir Jaranowski
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

import java.util.List;
import java.util.Map;
import java.util.Optional;

import lombok.AccessLevel;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.repository.RepositorySystem;
import org.apache.maven.shared.utils.logging.MessageBuilder;
import org.apache.maven.shared.utils.logging.MessageUtils;
import org.simplify4u.plugins.pgp.ArtifactInfo;
import org.simplify4u.plugins.pgp.KeyInfo;
import org.simplify4u.plugins.pgp.RevocationSignatureInfo;
import org.simplify4u.plugins.pgp.SignatureCheckResult;
import org.simplify4u.plugins.pgp.SignatureInfo;
import org.simplify4u.plugins.pgp.SignatureStatus;

/**
 * Show information about artifact signature.
 *
 * @author Slawomir Jaranowski
 * @since 1.10.0
 */
@Slf4j
@Mojo(name = ShowMojo.MOJO_NAME, requiresOnline = true, requiresProject = false)
public class ShowMojo extends AbstractPGPMojo {

    public static final String MOJO_NAME = "show";

    @Inject
    private RepositorySystem repositorySystem;

    /**
     * Show signature for pom files also.
     *
     * @since 1.10.0
     */
    @Setter(AccessLevel.PACKAGE)
    @Parameter(property = "showPom", defaultValue = "false")
    protected boolean showPom;

    /**
     * A artifact name to show pgp signature in format <code>groupId:artifactId:version[:packaging[:classifier]]</code>.
     *
     * @since 1.10.0
     */
    @Parameter(property = "artifact", required = true)
    @Setter(AccessLevel.PACKAGE)
    private String artifact;

    @Override
    protected String getMojoName() {
        return MOJO_NAME;
    }

    @Override
    protected void executeConfiguredMojo() {

        Artifact artifactToCheck = prepareArtifactToCheck();

        List<Artifact> resolveArtifacts = artifactResolver.resolveArtifact(artifactToCheck, showPom);

        Map<Artifact, Artifact> artifactMap = artifactResolver.resolveSignatures(resolveArtifacts);

        Boolean result = artifactMap.entrySet().stream()
                .map(this::processArtifact)
                .reduce(true, (a, b) -> a && b);

        if (Boolean.FALSE.equals(result)) {
            throw new PGPMojoException("Some of artifact can't be checked");
        }
    }

    private boolean processArtifact(Map.Entry<Artifact, Artifact> artifactEntry) {

        Artifact artifactToCheck = artifactEntry.getKey();
        Artifact sig = artifactEntry.getValue();

        SignatureCheckResult signatureCheckResult = signatureUtils.checkSignature(artifactToCheck, sig, pgpKeysCache);

        MessageBuilder messageBuilder = MessageUtils.buffer();
        messageBuilder.newline();
        messageBuilder.newline();

        ArtifactInfo artifactInfo = signatureCheckResult.getArtifact();

        messageBuilder.a("Artifact:").newline();
        messageBuilder.a("\tgroupId:     ").strong(artifactInfo.getGroupId()).newline();
        messageBuilder.a("\tartifactId:  ").strong(artifactInfo.getArtifactId()).newline();
        messageBuilder.a("\ttype:        ").strong(artifactInfo.getType()).newline();
        Optional.ofNullable(artifactInfo.getClassifier()).ifPresent(
                classifier -> messageBuilder.a("\tclassifier:  ").strong(classifier).newline());
        messageBuilder.a("\tversion:     ").strong(artifactInfo.getVersion()).newline();
        if (signatureCheckResult.getStatus() == SignatureStatus.ARTIFACT_NOT_RESOLVED) {
            messageBuilder.a("\t").failure("artifact was not resolved  - try mvn -U ...").newline();
        }

        messageBuilder.newline();

        SignatureInfo signature = signatureCheckResult.getSignature();
        if (signature != null) {
            messageBuilder.a("PGP signature:").newline();
            messageBuilder.a("\tversion:     ").strong(signature.getVersion()).newline();
            messageBuilder.a("\talgorithm:   ")
                    .strong(signatureUtils.digestName(signature.getHashAlgorithm()) + " with "
                            + signatureUtils.keyAlgorithmName(signature.getKeyAlgorithm())).newline();
            messageBuilder.a("\tkeyId:       ").strong(signature.getKeyId()).newline();
            messageBuilder.a("\tcreate date: ").strong(signature.getDate()).newline();
            messageBuilder.a("\tstatus:      ");
            if (signatureCheckResult.getStatus() == SignatureStatus.SIGNATURE_VALID) {
                messageBuilder.success("valid");
            } else if (signatureCheckResult.getStatus() == SignatureStatus.KEY_REVOCATION) {
                messageBuilder.success("revoked key without public key - not checked");
            } else {
                messageBuilder.failure("invalid");
            }
            messageBuilder.newline();
        } else if (signatureCheckResult.getStatus() == SignatureStatus.SIGNATURE_NOT_RESOLVED) {
            messageBuilder.a("\t")
                    .failure("PGP signature was not resolved - try mvn -U ...").newline();
        }

        messageBuilder.newline();

        KeyInfo key = signatureCheckResult.getKey();
        if (key != null) {
            messageBuilder.a("PGP key:").newline();
            messageBuilder.a("\tversion:     ").strong(key.getVersion()).newline();
            messageBuilder.a("\talgorithm:   ")
                    .strong(signatureUtils.keyAlgorithmName(key.getAlgorithm())).newline();
            messageBuilder.a("\tbits:        ").strong(key.getBits()).newline();
            messageBuilder.a("\tfingerprint: ").strong(key.getFingerprint()).newline();
            Optional.ofNullable(key.getMaster()).ifPresent(masterKey ->
                    messageBuilder.a("\tmaster key:  ").strong(masterKey).newline()
            );
            messageBuilder.a("\tcreate date: ").strong(key.getDate()).newline();
            messageBuilder.a("\tuids:        ").strong(key.getUids()).newline();
            if (key.isRevoked()) {
                messageBuilder.strong("\tkey is revoked").newline();
            }
        }

        RevocationSignatureInfo revocationSignature = signatureCheckResult.getRevocationSignature();
        if (revocationSignature != null) {
            messageBuilder.newline();
            messageBuilder.a("Revocation signature:").newline();
            messageBuilder.a("\tcreate date: ").strong(revocationSignature.getDate()).newline();
            messageBuilder.a("\treason:      ").strong(revocationSignature.getReasonAsString()).newline();
            Optional.ofNullable(revocationSignature.getDescription())
                    .filter(desc -> !desc.isEmpty())
                    .ifPresent(desc ->
                            messageBuilder.a("\tdescription: ").strong(desc).newline());
        }

        messageBuilder.newline();

        Optional.ofNullable(signatureCheckResult.getErrorMessage()).ifPresent(errorMessage ->
                messageBuilder.failure(errorMessage).newline());

        LOGGER.info(messageBuilder.build());

        return signatureCheckResult.getStatus() == SignatureStatus.SIGNATURE_VALID;
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
