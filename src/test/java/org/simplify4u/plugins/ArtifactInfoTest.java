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

import static org.simplify4u.plugins.TestArtifactBuilder.testArtifact;
import static org.testng.Assert.assertTrue;

import org.apache.maven.artifact.Artifact;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * @author Slawomir Jaranowski.
 */
public class ArtifactInfoTest {

    private static final KeyInfo ANY_KEY = new KeyInfo("*");

    @DataProvider(name = "lists")
    public Object[][] artifactsList() {
        return new Object[][]{
                {"test.group:test:*", testArtifact().build(), true},
                {"test.group:test:1.1.1", testArtifact().build(), true},
                {"test.group:test:[1.1,2.0)", testArtifact().build(), true},
                {"test.group:test:[1.1,2.0)", testArtifact().version("2.0").build(), false},
                {"test.group:test:1.1.1", testArtifact().version("1.1.2").build(), false},
                {"test.group:test", testArtifact().build(), true},
                {"test.group:test", testArtifact().build(), true},
                {"test.*:test", testArtifact().build(), true},
                {"test.*", testArtifact().build(), true},
        };
    }

    @Test(dataProvider = "lists")
    public void testMatchArtifact(String pattern, Artifact artifact, boolean match) {

        ArtifactInfo artifactInfo = new ArtifactInfo(pattern, ANY_KEY);
        assertTrue(artifactInfo.isMatch(artifact) == match);
        assertTrue(artifactInfo.isKeyMatch(null, null));
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Invalid artifact definition: test.group:test:1.0.*")
    public void asteriskInVersionThrowException() {
        new ArtifactInfo("test.group:test:1.0.*", ANY_KEY);
    }
}
