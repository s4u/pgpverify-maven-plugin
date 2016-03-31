/*
 * Copyright 2014 Slawomir Jaranowski
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

package com.github.s4u.plugins;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import org.apache.maven.ProjectDependenciesResolver;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.ArtifactUtils;
import org.apache.maven.artifact.repository.ArtifactRepository;
import org.apache.maven.artifact.resolver.ArtifactNotFoundException;
import org.apache.maven.artifact.resolver.ArtifactResolutionException;
import org.apache.maven.artifact.resolver.ArtifactResolutionRequest;
import org.apache.maven.artifact.resolver.ArtifactResolutionResult;
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
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.codehaus.plexus.resource.loader.ResourceNotFoundException;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;


/**
 * Check PGP signature of dependency.
 *
 * @author Slawomir Jaranowski.
 */
@Mojo(name = "check", requiresProject = true, requiresDependencyResolution = ResolutionScope.TEST,
        defaultPhase = LifecyclePhase.VALIDATE)
public class PGPVerifyMojo extends AbstractMojo {

    @Parameter(property = "project", readonly = true, required = true)
    private MavenProject project;

    @Parameter(defaultValue = "${session}", readonly = true)
    private MavenSession session;

    @Component
    private ProjectDependenciesResolver resolver;

    @Component
    private RepositorySystem repositorySystem;

    @Component
    private KeysMap keysMap;

    @Parameter(defaultValue = "${localRepository}", readonly = true, required = true)
    private ArtifactRepository localRepository;

    @Parameter(defaultValue = "${project.remoteArtifactRepositories}", readonly = true, required = true)
    private List<ArtifactRepository> pomRemoteRepositories;

    /**
     * The directory for storing cached PGP public keys.
     *
     * @since 1.0.0
     */
    @Parameter(property = "pgpverify.keycache", defaultValue = "${settings.localRepository}/pgpkeys-cache", required = true)
    private File pgpKeysCachePath;

    /**
     * Scope used to build dependency list.
     *
     * @since 1.0.0
     */
    @Parameter(property = "pgpverify.scope", defaultValue = "test")
    private String scope;

    /**
     * PGP public key server address.
     *
     * @since 1.0.0
     */
    @Parameter(property = "pgpverify.keyserver", defaultValue = "hkps://hkps.pool.sks-keyservers.net", required = true)
    private String pgpKeyServer;

    /**
     * Fail the build if any dependency doesn't have a signature.
     *
     * @since 1.1.0
     */
    @Parameter(property = "pgpverify.failNoSignature", defaultValue = "false")
    private boolean failNoSignature;

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
     * <p>Specifies the location of the properties file which contains the map of dependency to pgp key.</p>
     *
     * <p>The syntax of each line of properties file is:<br/><br/>
     * <code>groupId:artifactId:version=pgpKey</code></p>
     *
     * <p>You can use <code>*</code> in <code>groupId, artefactId and version</code> as wildcard.</p>
     *
     * <p><code>pgpKey</code> must be written as hex number starting with 0x.
     * You can use <code>*</code> or <code>any</code> for match any pgp key.</p>
     *
     * <p>You can also omit <code>version</code> and <code>artifactId</code> which means any value for those fields.</p>
     *
     * @since 1.1.0
     */
    @Parameter(property = "pgpverify.keysMapLocation", defaultValue = "")
    private String keysMapLocation;

    private PGPKeysCache pgpKeysCache;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {

        prepareForKeys();

        try {
            Set<Artifact> resolve = resolver.resolve(project, Arrays.asList(scope.split(",")), session);
            if (verifyPomFiles) {
                resolve.addAll(getPomArtifacts(resolve));
            }

            Map<Artifact, Artifact> artifactToAsc = new HashMap<>();

            getLog().debug("Start resolving ASC files");
            for (Artifact a : resolve) {

                if (a.isSnapshot()) {
                    continue;
                }

                ArtifactResolutionRequest rreq = getArtifactResolutionRequestForAsc(a);
                ArtifactResolutionResult result = repositorySystem.resolve(rreq);
                if (result.isSuccess()) {
                    Artifact aAsc = rreq.getArtifact();
                    getLog().debug(aAsc.toString() + " " + aAsc.getFile());
                    artifactToAsc.put(a, aAsc);
                } else {
                    if (failNoSignature) {
                        getLog().error("No signature for " + a.getId());
                        throw new MojoExecutionException("No signature for " + a.getId());
                    } else {
                        getLog().warn("No signature for " + a.getId());
                    }
                }
            }

            boolean isAllSigOk = true;
            for (Map.Entry<Artifact, Artifact> artifactEntry : artifactToAsc.entrySet()) {

                boolean isLastOk = verifyPGPSignature(artifactEntry.getKey(),
                        artifactEntry.getKey().getFile(), artifactEntry.getValue().getFile());
                isAllSigOk = isAllSigOk && isLastOk;
            }

            if (!isAllSigOk) {
                throw new MojoExecutionException("PGP signature error");
            }
        } catch (ArtifactResolutionException | ArtifactNotFoundException e) {
            throw new MojoExecutionException(e.getMessage(), e);
        }
    }

    /**
     * Prepare cache and keys map.
     *
     * @throws MojoFailureException
     * @throws MojoExecutionException
     */
    private void prepareForKeys() throws MojoFailureException, MojoExecutionException {

        initCache();

        try {
            keysMap.load(keysMapLocation);
        } catch (ResourceNotFoundException | IOException e) {
            throw new MojoExecutionException("load keys map", e);
        }
    }

    /**
     * Create Artifact objects for all pom files corresponding to the artifacts that you send in.
     *
     * @param resolve Set of artifacts to obtain pom's for
     * @return Artifacts for all the pom files
     */
    private Set<Artifact> getPomArtifacts(Set<Artifact> resolve) throws MojoExecutionException {
        Set<Artifact> poms = new HashSet<>();

        for (Artifact a : resolve) {
            if (a.isSnapshot()) {
                continue;
            }

            ArtifactResolutionRequest rreq = getArtifactResolutionRequestForPom(a);
            ArtifactResolutionResult result = repositorySystem.resolve(rreq);
            if (result.isSuccess()) {
                poms.add(rreq.getArtifact());
            } else {
                getLog().error("No pom for " + a.getId());
                throw new MojoExecutionException("No pom for " + a.getId());
            }
        }
        return poms;
    }

    /**
     * Create ArtifactResolutionRequest for asc file corresponding to artifact.
     *
     * @param artifact artifact
     * @return new ArtifactResolutionRequest
     */
    private ArtifactResolutionRequest getArtifactResolutionRequestForAsc(Artifact artifact) {

        Artifact aAsc = repositorySystem.createArtifactWithClassifier(
                artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion(),
                artifact.getType() + ".asc", artifact.getClassifier());

        ArtifactResolutionRequest rreq = new ArtifactResolutionRequest();
        rreq.setArtifact(aAsc);
        rreq.setResolveTransitively(false);
        rreq.setLocalRepository(localRepository);
        rreq.setRemoteRepositories(pomRemoteRepositories);
        return rreq;
    }

    /**
     * Create ArtifactResolutionRequest for pom file corresponding to artifact.
     *
     * @param artifact artifact
     * @return new ArtifactResolutionRequest
     */
    private ArtifactResolutionRequest getArtifactResolutionRequestForPom(Artifact artifact) {

        Artifact aAsc = repositorySystem.createArtifactWithClassifier(
                artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion(),
                "pom", artifact.getClassifier());

        ArtifactResolutionRequest rreq = new ArtifactResolutionRequest();
        rreq.setArtifact(aAsc);
        rreq.setResolveTransitively(false);
        rreq.setLocalRepository(localRepository);
        rreq.setRemoteRepositories(pomRemoteRepositories);
        return rreq;
    }

    private void initCache() throws MojoFailureException {

        if (pgpKeysCachePath.exists()) {
            if (!pgpKeysCachePath.isDirectory()) {
                throw new MojoFailureException("PGP keys cache path exist but is not a directory: " + pgpKeysCachePath);
            }
        } else {
            if (pgpKeysCachePath.mkdirs()) {
                getLog().info("Create cache for PGP keys: " + pgpKeysCachePath);
            } else {
                throw new MojoFailureException("Cache directory create error");
            }
        }

        try {
            pgpKeysCache = new PGPKeysCache(getLog(), pgpKeysCachePath, pgpKeyServer);
        } catch (URISyntaxException | IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            throw new MojoFailureException(e.getMessage(), e);
        }
    }

    private boolean verifyPGPSignature(Artifact artifact, File artifactFile, File signatureFile) throws MojoFailureException {

        final Map<Integer, String> weakSignatures = ImmutableMap.<Integer, String>builder()
                .put(1, "MD5")
                .put(4, "DOUBLE_SHA")
                .put(5, "MD2")
                .put(6, "TIGER_192")
                .put(7, "HAVAL_5_160")
                .put(11, "SHA224")
                .build();

        getLog().debug("Artifact file: " + artifactFile);
        getLog().debug("Artifact sign: " + signatureFile);

        try {
            InputStream sigInputStream = PGPUtil.getDecoderStream(new FileInputStream(signatureFile));
            PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(sigInputStream, new BcKeyFingerprintCalculator());
            PGPSignatureList sigList = (PGPSignatureList) pgpObjectFactory.nextObject();
            if (sigList == null) {
                throw new MojoFailureException("Invalid signature file: " + signatureFile);
            }
            PGPSignature pgpSignature = sigList.get(0);

            PGPPublicKey publicKey = pgpKeysCache.getKey(pgpSignature.getKeyID());

            if (!keysMap.isValidKey(artifact, publicKey)) {
                String msg = String.format("%s=0x%X", ArtifactUtils.key(artifact), publicKey.getKeyID());
                String keyUrl = pgpKeysCache.getUrlForShowKey(publicKey.getKeyID());
                getLog().error(String.format("Not allowed artifact %s and keyID:\n\t%s\n\t%s\n", artifact.getId(), msg, keyUrl));
                return false;
            }

            pgpSignature.init(new BcPGPContentVerifierBuilderProvider(), publicKey);

            try (InputStream inArtifact = new BufferedInputStream(new FileInputStream(artifactFile))) {

                int t;
                while ((t = inArtifact.read()) >= 0) {
                    pgpSignature.update((byte) t);
                }
            }

            String msgFormat = "%s PGP Signature %s\n       KeyId: 0x%X UserIds: %s";
            if (pgpSignature.verify()) {
                getLog().info(String.format(msgFormat, artifact.getId(),
                        "OK", publicKey.getKeyID(), Lists.newArrayList(publicKey.getUserIDs())));
                if (weakSignatures.containsKey(pgpSignature.getHashAlgorithm())) {
                    if (failWeakSignature) {
                        getLog().error("Weak signature algorithm used: "
                                + weakSignatures.get(pgpSignature.getHashAlgorithm()));
                        throw new MojoFailureException("Weak signature algorithm used: "
                                + weakSignatures.get(pgpSignature.getHashAlgorithm()));
                    } else {
                        getLog().warn("Weak signature algorithm used: "
                                + weakSignatures.get(pgpSignature.getHashAlgorithm()));
                    }
                }
                return true;
            } else {
                getLog().warn(String.format(msgFormat, artifact.getId(),
                        "ERROR", publicKey.getKeyID(), Lists.newArrayList(publicKey.getUserIDs())));
                getLog().warn(artifactFile.toString());
                getLog().warn(signatureFile.toString());
                return false;
            }

        } catch (IOException | PGPException e) {
            throw new MojoFailureException(e.getMessage(), e);
        }
    }
}

