/*
 * Copyright 2017 Slawomir Jaranowski
 * Portions Copyright 2017-2018 Wren Security.
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
import java.io.InputStream;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
import org.simplify4u.plugins.skipfilters.ProvidedDependencySkipper;
import org.simplify4u.plugins.skipfilters.ReactorDependencySkipper;
import org.simplify4u.plugins.skipfilters.SkipFilter;
import org.simplify4u.plugins.skipfilters.SnapshotDependencySkipper;
import org.simplify4u.plugins.skipfilters.SystemDependencySkipper;

/**
 * Check PGP signature of dependency.
 *
 * @author Slawomir Jaranowski.
 */
@Mojo(name = "check", requiresProject = true, requiresDependencyResolution = ResolutionScope.TEST,
        defaultPhase = LifecyclePhase.VALIDATE)
public class PGPVerifyMojo extends AbstractMojo {

    private static final String PGP_VERIFICATION_RESULT_FORMAT = "%s PGP Signature %s\n       KeyId: 0x%X UserIds: %s";

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
    private List<ArtifactRepository> remoteRepositories;

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
     * <p>Specifies the location of a file that contains the map of dependencies to PGP
     * key.</p>
     *
     * <p>The format of the file is similar to, but more flexible than, a Java properties file.
     * The syntax of each line of properties file is:<br/><br/>
     * <code>groupId:artifactId:version=pgpKey</code></p>
     *
     * <p>You can use <code>*</code> in <code>groupId, artifactId and version</code> as
     * wildcard.</p>
     *
     * <p><code>pgpKey</code> must be written as hex number starting with 0x.
     * You can use <code>*</code> or <code>any</code> for match any pgp key.
     * If the pgpKey is an empty string, pgp-verify will expect the package to
     * be unsigned. Please refer to <code>strictNoSignature</code> configuration
     * parameter for its use.</p>
     *
     * <p>You can also omit <code>version</code> and <code>artifactId</code> which means any value
     * for those fields.</p>
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

    private List<SkipFilter> skipFilters;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("Skipping pgpverify:check");
        } else {
            prepareSkipFilters();
            prepareForKeys();

            try {
                verifyArtifacts(getArtifactsToVerify());
            } catch (ArtifactResolutionException | ArtifactNotFoundException e) {
                throw new MojoExecutionException(e.getMessage(), e);
            }
        }
    }

    private void prepareSkipFilters() {
        final List<SkipFilter> filters = new LinkedList<>();

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

        this.skipFilters = filters;
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
     * Gets all of the artifacts that PGPVerify is going to check.
     *
     * @return The set of artifacts on which to check PGP signatures.
     *
     * @throws ArtifactResolutionException
     * @throws ArtifactNotFoundException
     */
    private Set<Artifact> getArtifactsToVerify()
    throws ArtifactResolutionException, ArtifactNotFoundException {
        Set<Artifact> artifacts =
            resolver.resolve(project, Arrays.asList(scope.split(",")), session);

        if (verifyPomFiles) {
            artifacts.addAll(getPomArtifacts(artifacts));
        }

        return artifacts;
    }

    /**
     * Create Artifact objects for all pom files corresponding to the artifacts that you send in.
     *
     * @param   artifacts
     *          Set of artifacts to obtain pom's for
     *
     * @return  Artifacts for all the pom files
     */
    private Set<Artifact> getPomArtifacts(Set<Artifact> artifacts) {
        Set<Artifact> poms = new HashSet<>();

        for (Artifact artifact : artifacts) {
            if (shouldSkipArtifact(artifact)) {
                continue;
            }

            ArtifactResolutionRequest rreq = getArtifactResolutionRequestForPom(artifact);
            ArtifactResolutionResult result = repositorySystem.resolve(rreq);

            if (result.isSuccess()) {
                poms.add(rreq.getArtifact());
            } else {
                getLog().warn("No pom for " + artifact.getId());
            }
        }

        return poms;
    }

    /**
     * Performs PGP verification of all of the provided artifacts.
     *
     * @param   artifacts
     *          The artifacts to verify.
     *
     * @throws  MojoExecutionException
     * @throws  MojoFailureException
     */
    private void verifyArtifacts(Set<Artifact> artifacts)
    throws MojoExecutionException, MojoFailureException {
        final Map<Artifact, Artifact> artifactToAsc = new HashMap<>();

        getLog().debug("Start resolving ASC files");

        for (Artifact artifact : artifacts) {
            final Artifact ascArtifact = resolveAscArtifact(artifact);

            if (ascArtifact != null || strictNoSignature) {
                artifactToAsc.put(artifact, ascArtifact);
            }
        }

        verifyArtifactSignatures(artifactToAsc);
    }

    /**
     * Retrieves the PGP signature file that corresponds to the given Maven artifact.
     *
     * @param   artifact
     *          The artifact for which a signature file is desired.
     * @return  Either a Maven artifact for the signature file, or {@code null} if the signature
     *          file could not be retrieved.
     *
     * @throws  MojoExecutionException
     *          If the signature could not be retrieved and the Mojo has been configured to fail
     *          on a missing signature.
     */
    private Artifact resolveAscArtifact(Artifact artifact) throws MojoExecutionException {
        Artifact ascArtifact = null;

        if (!shouldSkipArtifact(artifact)) {
            final ArtifactResolutionRequest ascReq = getArtifactResolutionRequestForAsc(artifact);
            final ArtifactResolutionResult ascResult = repositorySystem.resolve(ascReq);

            if (ascResult.isSuccess()) {
                ascArtifact = ascReq.getArtifact();

                getLog().debug(ascArtifact.toString() + " " + ascArtifact.getFile());
            } else {
                if (failNoSignature) {
                    getLog().error("No signature for " + artifact.getId());
                    throw new MojoExecutionException("No signature for " + artifact.getId());
                } else if (!strictNoSignature) {
                    getLog().warn("No signature for " + artifact.getId());
                }
            }
        }

        return ascArtifact;
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
                artifact.getType(), artifact.getClassifier());

        ArtifactResolutionRequest rreq = new ArtifactResolutionRequest();

        aAsc.setArtifactHandler(new AscArtifactHandler(aAsc));

        rreq.setArtifact(aAsc);
        rreq.setResolveTransitively(false);
        rreq.setLocalRepository(localRepository);
        rreq.setRemoteRepositories(remoteRepositories);

        return rreq;
    }

    /**
     * Create ArtifactResolutionRequest for pom file corresponding to artifact.
     *
     * @param artifact artifact
     * @return new ArtifactResolutionRequest
     */
    private ArtifactResolutionRequest getArtifactResolutionRequestForPom(Artifact artifact) {
        Artifact aAsc = repositorySystem.createProjectArtifact(
                artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion());

        ArtifactResolutionRequest rreq = new ArtifactResolutionRequest();
        rreq.setArtifact(aAsc);
        rreq.setResolveTransitively(false);
        rreq.setLocalRepository(localRepository);
        rreq.setRemoteRepositories(remoteRepositories);

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

    private boolean verifyPGPSignature(Artifact artifact, Artifact ascArtifact)
    throws MojoFailureException {
        if (ascArtifact == null) {
            return verifySignatureUnavailable(artifact);
        }
        final File artifactFile = artifact.getFile();
        final File signatureFile = ascArtifact.getFile();
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

            if (weakSignatures.containsKey(pgpSignature.getHashAlgorithm())) {
                final String logMessageWeakSignature = "Weak signature algorithm used: "
                        + weakSignatures.get(pgpSignature.getHashAlgorithm());
                if (failWeakSignature) {
                    getLog().error(logMessageWeakSignature);
                    throw new MojoFailureException(logMessageWeakSignature);
                } else {
                    getLog().warn(logMessageWeakSignature);
                }
            }

            PGPPublicKey publicKey = pgpKeysCache.getKey(pgpSignature.getKeyID());

            if (!keysMap.isValidKey(artifact, publicKey)) {
                String msg = String.format("%s=0x%X", ArtifactUtils.key(artifact), publicKey.getKeyID());
                String keyUrl = pgpKeysCache.getUrlForShowKey(publicKey.getKeyID());
                getLog().error(String.format("Not allowed artifact %s and keyID:%n\t%s%n\t%s%n", artifact.getId(), msg, keyUrl));
                return false;
            }

            pgpSignature.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
            PGPSignatures.readFileContentInto(pgpSignature, artifactFile);
            if (pgpSignature.verify()) {
                final String logMessageOK = String.format(PGP_VERIFICATION_RESULT_FORMAT, artifact.getId(),
                        "OK", publicKey.getKeyID(), Lists.newArrayList(publicKey.getUserIDs()));
                if (quiet) {
                    getLog().debug(logMessageOK);
                } else {
                    getLog().info(logMessageOK);
                }
                return true;
            } else {
                getLog().warn(String.format(PGP_VERIFICATION_RESULT_FORMAT, artifact.getId(),
                        "ERROR", publicKey.getKeyID(), Lists.newArrayList(publicKey.getUserIDs())));
                getLog().warn(artifactFile.toString());
                getLog().warn(signatureFile.toString());
                return false;
            }

        } catch (IOException | PGPException e) {
            throw new MojoFailureException(e.getMessage(), e);
        }
    }

    /**
     * Verify if unsigned artifact is correctly listed in keys map.
     *
     * @param artifact the artifact which is supposedly unsigned
     * @return Returns <code>true</code> if correctly missing according to keys map,
     * or <code>false</code> if verification fails.
     */
    private boolean verifySignatureUnavailable(final Artifact artifact) {
        if (keysMap.isNoKey(artifact)) {
            final String logMessage = String.format("%s PGP Signature unavailable, consistent with keys map.",
                    artifact.getId());
            if (quiet) {
                getLog().debug(logMessage);
            } else {
                getLog().info(logMessage);
            }
            return true;
        }
        getLog().error("Unsigned artifact not listed in keys map: " + artifact.getId());
        return false;
    }

    /**
     * Indicates whether or not an artifact should be skipped, based on the configuration of this
     * mojo.
     *
     * @param   artifact
     *          The artifact being considered for verification.
     *
     * @return  {@code true} if the artifact should be skipped; {@code false} if it should be
     *          processed.
     */
    private boolean shouldSkipArtifact(final Artifact artifact) {
        for (final SkipFilter filter : this.skipFilters) {
            if (filter.shouldSkipArtifact(artifact)) {
                return true;
            }
        }

        return false;
    }
}

