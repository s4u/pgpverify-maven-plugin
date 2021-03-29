/*
 * Copyright 2020 Slawomir Jaranowski
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.simplify4u.plugins.TestArtifactBuilder.testArtifact;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.versioning.InvalidVersionSpecificationException;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * @author Slawomir Jaranowski.
 */
public class ArtifactPatternTest {

    @DataProvider(name = "lists")
    public Object[][] artifactsList() {
        return new Object[][]{
                {"Test.Group:tesT:*", testArtifact().build(), true},
                {"test.group:test:*", testArtifact().version("1.0.0.M5").build(), true},
                {"test.group:test:*", testArtifact().version("0.0.0.M1").build(), true},
                {"test.group:test:3.0.0-M1", testArtifact().version("3.0.0-M1").build(), true},
                {"test.group:test:3.0.0-M1", testArtifact().version("3.0.0-m1").build(), true},
                {"test.group:test:1.1.1", testArtifact().build(), true},
                {"test.group:test:jar:1.1.1", testArtifact().build(), true},
                {"test.group:test:pom:1.1.1", testArtifact().build(), false},
                {"test.group:test:[1.1,2.0)", testArtifact().build(), true},
                {"test.group:test:pom:[1.1,2.0)", testArtifact().build(), false},
                {"test.group:test:[1.1,2.0)", testArtifact().version("2.0").build(), false},
                {"test.group:test:1.1.1", testArtifact().version("1.1.2").build(), false},
                {"test.group:test", testArtifact().build(), true},
                {"test.group", testArtifact().build(), true},
                {"test.group:*:jar", testArtifact().artifactId("test2").build(), true},
                {"test.group:*:pom", testArtifact().artifactId("test2").build(), false},
                {"test.group.*:test", testArtifact().build(), true},
                {"test.group.*:test", testArtifact().groupId("test.group.next").build(), true},
                {"test.group.*:test", testArtifact().groupId("test.groupnext").build(), false},
                {"test.group:test", testArtifact().packaging("pom").build(), true},
                {"test.group:test:pom", testArtifact().packaging("pom").build(), true},
                {"test.group:test:jar", testArtifact().packaging("pom").build(), false},
                {"test.*:test", testArtifact().build(), true},
                {"test.*", testArtifact().build(), true},
        };
    }

    @Test(dataProvider = "lists")
    public void testMatchArtifact(String pattern, Artifact artifact, boolean match) {

        ArtifactPattern artifactPattern = new ArtifactPattern(pattern);
        assertThat(artifactPattern.isMatch(new ArtifactData(artifact))).isEqualTo(match);
    }

    @Test
    public void asteriskInVersionThrowException() {

        assertThatCode(() -> new ArtifactPattern("test.group:test:1.0.*"))
                .isExactlyInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid artifact definition: test.group:test:1.0.*")
                .hasCauseExactlyInstanceOf(InvalidVersionSpecificationException.class)
                .hasRootCauseMessage("Invalid maven version range: 1.0.*");
    }

    @Test
    public void wrongVersionThrowException() {

        assertThatCode(() -> new ArtifactPattern("test.group:test:[1.0.0"))
                .isExactlyInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid artifact definition: test.group:test:[1.0.0")
                .hasCauseExactlyInstanceOf(InvalidVersionSpecificationException.class)
                .hasRootCauseMessage("Unbounded range: [1.0.0");
    }

    @Test
    public void twoInstanceWithTheSamePatternShouldBeEqual() {
        ArtifactPattern artifactPattern1 = new ArtifactPattern("test.group.*:test*");
        ArtifactPattern artifactPattern2 = new ArtifactPattern("test.group.*:test*");

        assertThat(artifactPattern1)
                .isNotSameAs(artifactPattern2)
                .isEqualTo(artifactPattern2)
                .hasSameHashCodeAs(artifactPattern2);
    }
}
