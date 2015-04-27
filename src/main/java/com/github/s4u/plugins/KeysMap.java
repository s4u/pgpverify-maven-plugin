/*
 * Copyright 2015 Slawomir Jaranowski
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

import com.google.common.base.Strings;
import org.apache.maven.artifact.Artifact;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.component.annotations.Requirement;
import org.codehaus.plexus.resource.ResourceManager;
import org.codehaus.plexus.resource.loader.ResourceNotFoundException;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * @author Slawomir Jaranowski.
 */
@Component(role = KeysMap.class)
public class KeysMap {

    @Requirement
    private ResourceManager resourceManager;

    private final List<ArtifactInfo> keysMapList = new ArrayList<>();

    /**
     * Properties.load recognize ':' as key value separator.
     * This reader adds backlash before ':' char.
     */
    class Reader extends InputStream {

        private final InputStream inputStream;
        private Character backSpace;

        public Reader(InputStream inputStream) {
            this.inputStream = inputStream;
        }

        @Override
        public int read() throws IOException {

            int c;
            if (backSpace == null) {
                c = inputStream.read();
            } else {
                c = backSpace;
                backSpace = null;
                return c;
            }

            if (c == ':') {
                backSpace = ':';
                return '\\';
            }
            return c;
        }
    }


    public void load(String locale) throws ResourceNotFoundException, IOException {

        if (Strings.isNullOrEmpty(locale) || Strings.isNullOrEmpty(locale.trim())) {
            return;
        }

        InputStream inputStream = resourceManager.getResourceAsInputStream(locale);

        Properties properties = new Properties();
        properties.load(new Reader(inputStream));
        processProps(properties);
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

    private void processProps(Properties properties) {

        for (String propKey : properties.stringPropertyNames()) {
            ArtifactInfo artifactInfo = createArtifactInfo(propKey, properties.getProperty(propKey));
            keysMapList.add(artifactInfo);
        }
    }

    private ArtifactInfo createArtifactInfo(String strArtifact, String strKeys) {
        return new ArtifactInfo(strArtifact, new KeyInfo(strKeys));
    }
}
