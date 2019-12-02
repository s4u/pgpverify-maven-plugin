/*
 * Copyright 2017 Slawomir Jaranowski
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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.google.common.base.Strings;
import org.apache.maven.artifact.Artifact;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.component.annotations.Requirement;
import org.codehaus.plexus.resource.ResourceManager;
import org.codehaus.plexus.resource.loader.ResourceNotFoundException;

/**
 * @author Slawomir Jaranowski.
 */
@Component(role = KeysMap.class)
public class KeysMap {

    @Requirement
    private ResourceManager resourceManager;

    private final List<ArtifactInfo> keysMapList = new ArrayList<>();

    public void load(String locale) throws ResourceNotFoundException, IOException {
        if (!Strings.isNullOrEmpty(locale) && !Strings.isNullOrEmpty(locale.trim())) {

            try (final InputStream inputStream = resourceManager.getResourceAsInputStream(locale)) {
                loadKeysMap(inputStream);
            }
        }
    }

    public boolean isNoKey(Artifact artifact) {
        for (ArtifactInfo artifactInfo : keysMapList) {
            if (artifactInfo.isMatch(artifact)) {
                return artifactInfo.isNoKey();
            }
        }
        return false;
    }

    public boolean isValidKey(Artifact artifact, PGPPublicKey key) {
        if (keysMapList.isEmpty()) {
            return true;
        }

        for (ArtifactInfo artifactInfo : keysMapList) {
            if (artifactInfo.isMatch(artifact)) {
                return artifactInfo.isKeyMatch(key);
            }
        }

        return false;
    }

    private void loadKeysMap(final InputStream inputStream) throws IOException {
        final BufferedReader mapReader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.US_ASCII));
        String currentLine;

        while ((currentLine = mapReader.readLine()) != null) {
            if (!currentLine.isEmpty() && !isCommentLine(currentLine)) {
                final String[] parts = currentLine.split("=");

                if (parts.length > 2) {
                    throw new IllegalArgumentException(
                        "Property line is malformed: " + currentLine);
                }

                ArtifactInfo artifactInfo = createArtifactInfo(parts[0], parts.length == 1 ? "" : parts[1]);
                keysMapList.add(artifactInfo);
            }
        }
    }

    private boolean isCommentLine(final String line) {
        return !line.isEmpty() && line.charAt(0) == '#';
    }

    private ArtifactInfo createArtifactInfo(String strArtifact, String strKeys) {
        return new ArtifactInfo(strArtifact.trim(), new KeyInfo(strKeys.trim()));
    }
}
