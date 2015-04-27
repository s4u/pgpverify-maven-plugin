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

import org.apache.maven.artifact.Artifact;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static com.github.s4u.plugins.TestUtils.getArtifact;
import static org.testng.Assert.assertTrue;

/**
 * @author Slawomir Jaranowski.
 */
public class ArtifactInfoTest {

    private static final KeyInfo ANY_KEY = new KeyInfo("*");

    @DataProvider(name = "lists")
    public Object[][] artifactsList() {
        return new Object[][]{
                {"test.group:test:1.1.1", getArtifact("test.group", "test", "1.1.1") },
                {"test.group:test:1.1.*", getArtifact("test.group", "test", "1.1.5") },
                {"test.group:test", getArtifact("test.group", "test", "1.2.3") },
                {"test.*:test", getArtifact("test.group", "test", "1.2.3") },
                {"test.*", getArtifact("test.group", "test-test", "1.2.3") },
        };
    }

    @Test(dataProvider = "lists")
    public void testMatchArtifact(String pattern, Artifact artifact) {

        ArtifactInfo artifactInfo = new ArtifactInfo(pattern, ANY_KEY);
        assertTrue(artifactInfo.isMatch(artifact));
        assertTrue(artifactInfo.isKeyMatch(null));
    }
}
