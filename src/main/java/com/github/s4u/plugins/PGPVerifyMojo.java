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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;


/**
 * Check PGP signature of dependency.
 *
 * @author Slawomir Jaranowski.
 */
@Mojo(name = "check", requiresProject = true, requiresDependencyResolution = ResolutionScope.TEST,
        defaultPhase = LifecyclePhase.VALIDATE)
public class PGPVerifyMojo extends AbstractMojo {

    @Parameter(property = "project", readonly = true, required = true)
    private MavenProject project = null;

    @Component
    private MavenSession session = null;

    @Component
    protected ProjectDependenciesResolver resolver;

    @Component
    private RepositorySystem repositorySystem = null;

    @Parameter(defaultValue = "${localRepository}", readonly = true, required = true)
    private ArtifactRepository localRepository = null;

    @Parameter(defaultValue = "${project.remoteArtifactRepositories}", readonly = true, required = true)
    private List<ArtifactRepository> pomRemoteRepositories = null;

    /**
     * The directory for storing cached PGP public keys.
     */
    @Parameter(property = "pgpverify.keycache", defaultValue = "${settings.localRepository}/pgpkeys-cache", required = true)
    private File pgpKeysCachePath;

    /**
     * Scope used to build dependency list.
     */
    @Parameter(property = "pgpverify.scope", defaultValue = "test")
    private String scope;

    /**
     * PGP public key server address.
     */
    @Parameter(property = "pgpverify.keyserver", defaultValue = "hkp://pool.sks-keyservers.net", required = true)
    private String pgpKeyServer;

    private PGPKeysCache pgpKeysCache;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {

        initCache();

        try {

            Set<Artifact> resolve = resolver.resolve(project, Arrays.asList(scope.split(",")), session);

            Map<Artifact, Artifact> artifactToAsc = new HashMap<>();

            getLog().debug("Start resolving ASC files");
            for (Artifact a : resolve) {

                if (a.isSnapshot()) {
                    continue;
                }

                Artifact aAsc = repositorySystem.createArtifactWithClassifier(
                        a.getGroupId(), a.getArtifactId(), a.getVersion(),
                        a.getType() + ".asc", a.getClassifier());

                ArtifactResolutionRequest rreq = new ArtifactResolutionRequest();
                rreq.setArtifact(aAsc);
                rreq.setResolveTransitively(false);
                rreq.setLocalRepository(localRepository);
                rreq.setRemoteRepositories(pomRemoteRepositories);

                ArtifactResolutionResult result = repositorySystem.resolve(rreq);
                if (result.isSuccess()) {
                    getLog().debug(aAsc.toString() + " " + aAsc.getFile());
                    artifactToAsc.put(a, aAsc);
                } else {
                    getLog().warn("No signature for " + a);
                }
            }

            boolean isAllSigOk = true;
            for (Map.Entry<Artifact, Artifact> artifactEntry : artifactToAsc.entrySet()) {
                isAllSigOk = isAllSigOk && verifyPGPSignature(artifactEntry.getKey(),
                        artifactEntry.getKey().getFile(), artifactEntry.getValue().getFile());
            }

            if (!isAllSigOk) {
                throw new MojoExecutionException("PGP signature error");
            }
        } catch (ArtifactResolutionException | ArtifactNotFoundException e) {
            throw new MojoExecutionException(e.getMessage(), e);
        }

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
        } catch (URISyntaxException e) {
            throw new MojoFailureException(e.getMessage(), e);
        }
    }

    private boolean verifyPGPSignature(Artifact artifact, File artifactFile, File signatureFile) throws MojoFailureException {

        getLog().debug("Artifact file: " + artifactFile);
        getLog().debug("Artifact sign: " + signatureFile);

        try {
            InputStream sigInputStream = PGPUtil.getDecoderStream(new FileInputStream(signatureFile));
            PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(sigInputStream);
            PGPSignatureList sigList = (PGPSignatureList) pgpObjectFactory.nextObject();
            PGPSignature pgpSignature = sigList.get(0);

            PGPPublicKey publicKey = pgpKeysCache.getKey(pgpSignature.getKeyID());

            pgpSignature.init(new BcPGPContentVerifierBuilderProvider(), publicKey);

            try (InputStream inArtifact = new BufferedInputStream(new FileInputStream(artifactFile))) {

                int t;
                while ((t = inArtifact.read()) >= 0) {
                    pgpSignature.update((byte) t);
                }
            }

            String msgFormat = "%s PGP Signature %s\n       KeyId: 0x%X UserIds: %s";
            if (pgpSignature.verify()) {
                getLog().info(String.format(msgFormat, ArtifactUtils.key(artifact),
                        "OK", publicKey.getKeyID(), Lists.newArrayList(publicKey.getUserIDs())));
                return true;
            } else {
                getLog().warn(String.format(msgFormat, ArtifactUtils.key(artifact),
                        "ERROR", publicKey.getKeyID(), Lists.newArrayList(publicKey.getUserIDs())));
                getLog().warn(artifactFile.toString());
                getLog().warn(signatureFile.toString());
                return false;
            }

        } catch (IOException | PGPException | SignatureException e) {
            throw new MojoFailureException(e.getMessage(), e);
        }
    }
}

