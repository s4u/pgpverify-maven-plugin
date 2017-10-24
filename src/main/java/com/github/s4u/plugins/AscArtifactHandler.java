package com.github.s4u.plugins;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.handler.ArtifactHandler;

/**
 * Wrapper around an {@code ArtifactHandler} for an artifact, to retrieve its
 * PGP signature file.
 */
public class AscArtifactHandler implements ArtifactHandler {
    private ArtifactHandler wrappedHandler;

    /**
     * Initializes a new ASC Artifact Handler for the provided artifact.
     *
     * @param targetArtifact
     *   The artifact for which a GPG signature artifact is desired.
     */
    public AscArtifactHandler(Artifact targetArtifact) {
      this(targetArtifact.getArtifactHandler());
    }

    /**
     * Initializes a new ASC Artifact Handler to wrap the provided regular
     * artifact handler.
     *
     * The GPG signature file returned will correspond to the artifact that the
     * specified artifact handler resolves.
     *
     * @param wrappedHandler
     *   An artifact handler that will be wrapped by this ASC Artifact Handler,
     *   such that all information about the target artifact come from the
     *   provided handler, except for the file extension (".asc").
     */
    public AscArtifactHandler(ArtifactHandler wrappedHandler) {
      this.wrappedHandler = wrappedHandler;
    }

    @Override
    public String getExtension() {
        return wrappedHandler.getExtension() + ".asc";
    }

    @Override
    public String getDirectory() {
        return wrappedHandler.getDirectory();
    }

    @Override
    public String getClassifier() {
        return wrappedHandler.getClassifier();
    }

    @Override
    public String getPackaging() {
        return wrappedHandler.getPackaging();
    }

    @Override
    public boolean isIncludesDependencies() {
        return wrappedHandler.isIncludesDependencies();
    }

    @Override
    public String getLanguage() {
        return wrappedHandler.getLanguage();
    }

    @Override
    public boolean isAddedToClasspath() {
        return wrappedHandler.isAddedToClasspath();
    }
}
