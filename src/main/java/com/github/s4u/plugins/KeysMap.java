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
import com.google.common.collect.Maps;
import org.apache.maven.artifact.Artifact;
import org.codehaus.plexus.resource.ResourceManager;
import org.codehaus.plexus.resource.loader.ResourceNotFoundException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Map;
import java.util.Properties;

/**
 * Created by grenville on 4/15/16.
 */
public class KeysMap {

    private final Map<ArtifactInfo, Long> keysMap;
    private final File keysMapLocation;

    public KeysMap(final File keysMapLocation, final ResourceManager resourceManager) throws ResourceNotFoundException, IOException {
        this.keysMapLocation = keysMapLocation;

        final Map<ArtifactInfo, Long> keysMap = Maps.newHashMap();
        if (keysMapLocation.exists()) {
            final Properties properties = new Properties();
            try(final InputStream inputStream = resourceManager.getResourceAsInputStream(keysMapLocation.getAbsolutePath())) {
                properties.load(inputStream);
            }

            for (String propKey : properties.stringPropertyNames()) {
                final String strKeyId = properties.getProperty(propKey);
                final Long keyId = new BigInteger(strKeyId, 16).longValue();
                final ArtifactInfo artifactInfo = new ArtifactInfo(propKey);
                keysMap.put(artifactInfo, keyId);
            }
        }
        this.keysMap = keysMap;
    }

    public boolean exists(final Artifact artifact) {
        return keysMap.containsKey(new ArtifactInfo(artifact));
    }

    public boolean isValid(final Artifact artifact, final long keyId) {

        if (keysMap.isEmpty()) {
            return true;
        }

        for (final ImmutableMap.Entry<ArtifactInfo, Long> entry : keysMap.entrySet()) {
            if (entry.getKey().isMatch(artifact)) {
                return entry.getValue().equals(keyId);
            }
        }

        return true;
    }

    public void addArtifactToKeyMapping(Artifact artifact, long keyId) {
        final ArtifactInfo artifactInfo = new ArtifactInfo(artifact);
        keysMap.put(artifactInfo, keyId);
    }

    public void save() throws IOException {
        if (keysMapLocation.exists()) {
            if(!keysMapLocation.delete()) {
                throw new IOException("Failed to delete key map.");
            }
        }

        final Properties properties = new Properties();
        for (final Map.Entry<ArtifactInfo, Long> entry : keysMap.entrySet()) {
            final String artifact = entry.getKey().toString();
            properties.put(artifact, Long.toHexString(entry.getValue()));
        }
        try (final OutputStream outputStream = new FileOutputStream(keysMapLocation)) {
            properties.store(outputStream, null);
        }
    }
}
