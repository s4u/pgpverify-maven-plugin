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
import java.util.HashMap;
import java.util.Map;
import javax.inject.Inject;
import javax.inject.Named;

import lombok.extern.slf4j.Slf4j;
import org.apache.maven.artifact.Artifact;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.codehaus.plexus.resource.ResourceManager;
import org.codehaus.plexus.resource.loader.ResourceNotFoundException;

/**
 * Store and manage information loaded from keysMap file.
 *
 * @author Slawomir Jaranowski.
 */
@Slf4j
@Named
public class KeysMap {

    private ResourceManager resourceManager;

    private final Map<ArtifactPattern, KeyItems> items = new HashMap<>();

    @Inject
    KeysMap(ResourceManager resourceManager) {
        this.resourceManager = resourceManager;
    }

    public void load(String locale) throws ResourceNotFoundException, IOException {
        if (locale != null && !locale.trim().isEmpty()) {
            try (final InputStream inputStream = resourceManager.getResourceAsInputStream(locale)) {
                loadKeysMap(inputStream, new KeysMapContext(locale));
            }
        }
        if (items.isEmpty()) {
            LOGGER.warn("No keysmap specified in configuration or keysmap contains no entries. PGPVerify will only " +
                    "check artifacts against their signature. File corruption will be detected. However, without a " +
                    "keysmap as a reference for trust, valid signatures of any public key will be accepted.");
        }
    }

    /**
     * Indicate whether some keysmap entries are actually loaded.
     *
     * @return Returns true if at least one entry exists in the keysmap, or false otherwise.
     */
    public boolean isEmpty() {
        return items.isEmpty();
    }

    /**
     * Artifact can has no signature.
     *
     * @param artifact artifact to test
     *
     * @return signature status
     */
    public boolean isNoSignature(Artifact artifact) {

        ArtifactData artifactData = new ArtifactData(artifact);

        return items.entrySet().stream()
                .filter(entry -> entry.getKey().isMatch(artifactData))
                .anyMatch(entry -> entry.getValue().isNoSignature());
    }

    /**
     * Artifact can has broken signature.
     *
     * @param artifact artifact to test
     *
     * @return broken signature status
     */
    public boolean isBrokenSignature(Artifact artifact) {

        ArtifactData artifactData = new ArtifactData(artifact);

        return items.entrySet().stream()
                .filter(entry -> entry.getKey().isMatch(artifactData))
                .anyMatch(entry -> entry.getValue().isBrokenSignature());
    }

    /**
     * Key for signature can be not found on public key servers.
     *
     * @param artifact artifact to test
     *
     * @return key missing status
     */
    public boolean isKeyMissing(Artifact artifact) {

        ArtifactData artifactData = new ArtifactData(artifact);

        return items.entrySet().stream()
                .filter(entry -> entry.getKey().isMatch(artifactData))
                .anyMatch(entry -> entry.getValue().isKeyMissing());
    }

    public boolean isWithKey(Artifact artifact) {

        ArtifactData artifactData = new ArtifactData(artifact);

        return items.entrySet().stream()
                .filter(entry -> entry.getKey().isMatch(artifactData))
                .anyMatch(entry -> !entry.getValue().isNoSignature());
    }

    public boolean isValidKey(Artifact artifact, PGPPublicKey key, PGPPublicKeyRing keyRing) {

        if (items.isEmpty()) {
            return true;
        }

        ArtifactData artifactData = new ArtifactData(artifact);

        return items.entrySet().stream()
                .filter(entry -> entry.getKey().isMatch(artifactData))
                .anyMatch(entry -> entry.getValue().isKeyMatch(key, keyRing));
    }

    private void loadKeysMap(final InputStream inputStream, KeysMapContext keysMapContext) throws IOException {

        BufferedReader mapReader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.US_ASCII)) {

            @Override
            public String readLine() throws IOException {
                keysMapContext.incLineNumber();
                return super.readLine();
            }
        };

        String currentLine;

        while ((currentLine = getNextLine(mapReader)) != null) {

            String[] parts = currentLine.split("=", 2);
            String artifactPatternStr = parts[0].trim();
            String keyItemsStr = parts.length == 1 ? "" : parts[1].trim();

            ArtifactPattern artifactPattern = new ArtifactPattern(artifactPatternStr);

            if (items.containsKey(artifactPattern)) {
                LOGGER.debug("Existing artifact pattern: {} - only update key items in {}",
                        artifactPatternStr, keysMapContext);
                items.get(artifactPattern).addKeys(keyItemsStr, keysMapContext);
            } else {
                items.put(artifactPattern, new KeyItems().addKeys(keyItemsStr, keysMapContext));
            }
        }
    }

    private static String getNextLine(BufferedReader mapReader) throws IOException {

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

    private static String getNextNotEmptyLine(BufferedReader readLine) throws IOException {

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

    private static String stripComments(String line) {
        if (line.length() < 1) {
            return line;
        }
        int hashIndex = line.indexOf('#');
        return hashIndex >= 0 ? line.substring(0, hashIndex).trim() : line;
    }

    // for testing purpose

    int size() {
        return items.size();
    }
}
