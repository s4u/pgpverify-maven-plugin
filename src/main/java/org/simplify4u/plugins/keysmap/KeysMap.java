/*
 * Copyright 2020 Slawomir Jaranowski
 * Portions Copyright 2020 Danny van Heumen
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
package org.simplify4u.plugins.keysmap;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import org.apache.maven.artifact.Artifact;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.component.annotations.Requirement;
import org.codehaus.plexus.resource.ResourceManager;
import org.codehaus.plexus.resource.loader.ResourceNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Slawomir Jaranowski.
 */
@Component(role = KeysMap.class, instantiationStrategy = "per-lookup")
public class KeysMap {

    private static final Logger LOG = LoggerFactory.getLogger(KeysMap.class);

    @Requirement
    private ResourceManager resourceManager;

    private final ArrayList<ArtifactInfo> keysMapList = new ArrayList<>();

    public void load(String locale) throws ResourceNotFoundException, IOException {
        if (locale != null && !locale.trim().isEmpty()) {
            try (final InputStream inputStream = resourceManager.getResourceAsInputStream(locale)) {
                loadKeysMap(inputStream);
            }
        }
        if (keysMapList.isEmpty()) {
            LOG.warn("No keysmap specified in configuration or keysmap contains no entries. PGPVerify will only " +
                    "check artifacts against their signature. File corruption will be detected. However, without a " +
                    "keysmap as a reference for trust, valid signatures of any public key will be accepted.");
        }
    }

    /**
     * Artifact can has no signature.
     *
     * @param artifact
     *         artifact to test
     *
     * @return signature status
     */
    public boolean isNoSignature(Artifact artifact) {

        return keysMapList.stream()
                .filter(artifactInfo -> artifactInfo.isMatch(artifact))
                .anyMatch(ArtifactInfo::isNoSignature);
    }

    /**
     * Artifact can has broken signature.
     *
     * @param artifact
     *         artifact to test
     *
     * @return broken signature status
     */
    public boolean isBrokenSignature(Artifact artifact) {

        return keysMapList.stream()
                .filter(artifactInfo -> artifactInfo.isMatch(artifact))
                .anyMatch(ArtifactInfo::isBrokenSignature);
    }

    /**
     * Key for signature can be not found on public key servers.
     *
     * @param artifact
     *         artifact to test
     *
     * @return key missing status
     */
    public boolean isKeyMissing(Artifact artifact) {

        return keysMapList.stream()
                .filter(artifactInfo -> artifactInfo.isMatch(artifact))
                .anyMatch(ArtifactInfo::isKeyMissing);
    }

    public boolean isWithKey(Artifact artifact) {
        for (ArtifactInfo artifactInfo : keysMapList) {
            if (artifactInfo.isMatch(artifact)) {
                return !artifactInfo.isNoSignature();
            }
        }
        return false;
    }

    public boolean isValidKey(Artifact artifact, PGPPublicKey key, PGPPublicKeyRing keyRing) {
        if (keysMapList.isEmpty()) {
            return true;
        }

        return keysMapList.stream()
                .filter(artifactInfo -> artifactInfo.isMatch(artifact))
                .anyMatch(artifactInfo -> artifactInfo.isKeyMatch(key, keyRing));
    }

    private void loadKeysMap(final InputStream inputStream) throws IOException {
        BufferedReader mapReader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.US_ASCII));
        String currentLine;

        while ((currentLine = getNextLine(mapReader)) != null) {
            String[] parts = currentLine.split("=", 2);
            ArtifactInfo artifactInfo = createArtifactInfo(parts[0], parts.length == 1 ? "" : parts[1]);
            keysMapList.add(artifactInfo);
        }
    }

    private String getNextLine(BufferedReader mapReader) throws IOException {

        StringBuilder nextLine = new StringBuilder();
        String line;

        while ((line = getNextNotEmptyLine(mapReader)) != null) {

            if (line.charAt(line.length() - 1) == '\\') {
                nextLine.append(line, 0, line.length() - 1);
                nextLine.append(" ");
            } else {
                nextLine.append(line);
                break;
            }
        }
        String ret = nextLine.toString().trim();
        return ret.length() == 0 ? null : ret;
    }

    private String getNextNotEmptyLine(BufferedReader readLine) throws IOException {

        String nextLine = null;
        String line;

        while ((line = readLine.readLine()) != null) {
            nextLine = stripComments(line.trim());
            if (!nextLine.isEmpty()) {
                break;
            }
        }

        return nextLine == null || nextLine.length() == 0 ? null : nextLine;
    }

    private String stripComments(String line) {
        if (line.length() < 1) {
            return line;
        }
        int hashIndex = line.indexOf('#');
        return hashIndex >= 0 ? line.substring(0, hashIndex).trim() : line;
    }

    private ArtifactInfo createArtifactInfo(String strArtifact, String strKeys) {
        return new ArtifactInfo(strArtifact.trim(), new KeyInfo(strKeys.trim()));
    }
}
