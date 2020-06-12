/*
 * Copyright 2020 Danny van Heumen
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

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.io.File;

import com.google.common.io.Files;

import org.apache.maven.artifact.Artifact;
import org.simplify4u.plugins.ValidationChecksum.Builder;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class ValidationChecksumTest {

    private File checksumdirectory = null;

    @BeforeMethod
    public void setUp() {
        this.checksumdirectory = Files.createTempDir();
    }

    @AfterMethod
    public void tearDown() {
        ValidationChecksum.Builder.deleteChecksum(checksumdirectory);
        this.checksumdirectory.delete();
    }

    @Test
    public void testValidationChecksumBuilderNullFile() {
        new ValidationChecksum.Builder().destination(null).artifacts(emptyList()).build();
    }

    @Test
    public void testValidationChecksumBuilderArtifactsNull() {
        final Builder builder = new ValidationChecksum.Builder().destination(checksumdirectory);
        assertThatCode(() -> builder.artifacts(null).build())
                .isExactlyInstanceOf(NullPointerException.class);
    }

    @Test
    public void testValidationChecksumBuilderArtifactsNotProvided() {
        final Builder builder = new ValidationChecksum.Builder().destination(checksumdirectory);
        assertThatCode(builder::build).isExactlyInstanceOf(IllegalStateException.class);
    }

    @Test
    public void testValidationChecksumBuilderChecksumEmptyCollection() {
        final Builder builder = new ValidationChecksum.Builder().destination(checksumdirectory);
        final ValidationChecksum checksum = builder.artifacts(emptyList()).build();
        assertThat(checksum).isNotNull();
        assertThat(checksum.checkValidation()).isFalse();
    }

    @Test
    public void testValidationChecksumBuilderChecksumArtifactsNullFails() {
        final Builder builder = new ValidationChecksum.Builder().destination(checksumdirectory);
        final Artifact a1 = TestArtifactBuilder.testArtifact().groupId("org.apache.maven.plugins")
                .artifactId("maven-compiler-plugin").packaging("jar").version("1.0").build();
        final Artifact a2 = TestArtifactBuilder.testArtifact().groupId("org.apache.commons").artifactId("commons-io")
                .packaging("jar").version("1.0").build();
        assertThatCode(() -> builder.artifacts(asList(a1, a2, null)).build())
                .isExactlyInstanceOf(NullPointerException.class);
    }

    @Test
    public void testValidationChecksumBuilderChecksumArtifactsRepeatedly() {
        final Builder builder = new ValidationChecksum.Builder().destination(checksumdirectory);
        final Artifact a1 = TestArtifactBuilder.testArtifact()
                .groupId("org.apache.maven.plugins").artifactId("maven-compiler-plugin")
                .packaging("jar").version("1.0").build();
        final Artifact a2 = TestArtifactBuilder.testArtifact()
                .groupId("org.apache.commons").artifactId("commons-io")
                .packaging("jar").version("1.0").build();
        final Artifact a3 = TestArtifactBuilder.testArtifact()
                .groupId("org.apache.commons").artifactId("commons-text")
                .packaging("jar").version("1.1.1-3").build();
        final ValidationChecksum checksum = builder.artifacts(asList(a1, a2, a3)).build();
        assertThat(checksum).isNotNull();
        assertThat(checksum.checkValidation()).isFalse();
        checksum.saveChecksum();
        assertThat(checksum.checkValidation()).isTrue();
        assertThat(checksum.checkValidation()).isTrue();
        assertThat(checksum.checkValidation()).isTrue();
    }

    @Test
    public void testValidationChecksumBuilderChecksumArtifactsDeterministicOrder() {
        final Builder builder = new ValidationChecksum.Builder().destination(checksumdirectory);
        final Artifact a1 = TestArtifactBuilder.testArtifact()
                .groupId("org.apache.maven.plugins").artifactId("maven-compiler-plugin")
                .packaging("jar").version("1.0").build();
        final Artifact a2 = TestArtifactBuilder.testArtifact()
                .groupId("org.apache.commons").artifactId("commons-io")
                .packaging("jar").version("1.0").build();
        final Artifact a3 = TestArtifactBuilder.testArtifact()
                .groupId("org.apache.commons").artifactId("commons-text")
                .packaging("jar").version("1.1.1-3").build();
        builder.artifacts(asList(a1, a2, a3)).build().saveChecksum();
        assertThat(builder.artifacts(asList(a1, a3, a2)).build().checkValidation()).isFalse();
        assertThat(builder.artifacts(asList(a2, a1, a3)).build().checkValidation()).isFalse();
        assertThat(builder.artifacts(asList(a2, a3, a1)).build().checkValidation()).isFalse();
        assertThat(builder.artifacts(asList(a3, a2, a1)).build().checkValidation()).isFalse();
        assertThat(builder.artifacts(asList(a3, a1, a2)).build().checkValidation()).isFalse();
        assertThat(builder.artifacts(asList(a1, a2, a3)).build().checkValidation()).isTrue();
    }

    @Test
    public void testValidationChecksumBuilderChecksumArtifactsDisabled() {
        final Builder builder = new ValidationChecksum.Builder().destination(checksumdirectory);
        final Artifact a1 = TestArtifactBuilder.testArtifact()
                .groupId("org.apache.maven.plugins").artifactId("maven-compiler-plugin")
                .packaging("jar").version("1.0").build();
        final Artifact a2 = TestArtifactBuilder.testArtifact()
                .groupId("org.apache.commons").artifactId("commons-io")
                .packaging("jar").version("1.0").build();
        final Artifact a3 = TestArtifactBuilder.testArtifact()
                .groupId("org.apache.commons").artifactId("commons-text")
                .packaging("jar").version("1.1.1-3").build();
        final ValidationChecksum checksum = builder.artifacts(asList(a1, a2, a3)).disabled(true).build();
        assertThat(checksum).isNotNull();
        assertThat(checksum.disabled()).isTrue();
        assertThat(checksum.checkValidation()).isFalse();
        checksum.saveChecksum();
    }
}