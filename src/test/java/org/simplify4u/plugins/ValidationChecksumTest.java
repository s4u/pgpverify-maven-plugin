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

import java.io.File;
import java.util.List;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.apache.maven.artifact.Artifact;
import org.junit.jupiter.api.io.TempDir;
import org.simplify4u.plugins.ValidationChecksum.Builder;
import org.junit.jupiter.api.Test;

class ValidationChecksumTest {

    @TempDir
    private File checksumdirectory = null;

    @Test
    void testValidationChecksumBuilderNullFile() {
        assertDoesNotThrow(() -> new ValidationChecksum.Builder().destination(null).artifacts(emptyList()).build());
    }

    @Test
    void testValidationChecksumBuilderArtifactsNull() {
        final Builder builder = new ValidationChecksum.Builder().destination(checksumdirectory);
        assertThatCode(() -> builder.artifacts(null))
                .isExactlyInstanceOf(NullPointerException.class);
    }

    @Test
    void testValidationChecksumBuilderArtifactsNotProvided() {
        final Builder builder = new ValidationChecksum.Builder().destination(checksumdirectory);
        assertThatCode(builder::build).isExactlyInstanceOf(IllegalStateException.class);
    }

    @Test
    void testValidationChecksumBuilderChecksumEmptyCollection() {
        final Builder builder = new ValidationChecksum.Builder().destination(checksumdirectory);
        final ValidationChecksum checksum = builder.artifacts(emptyList()).build();
        assertThat(checksum).isNotNull();
        assertThat(checksum.checkValidation()).isFalse();
    }

    @Test
    void testValidationChecksumBuilderChecksumArtifactsNullFails() {

        final Artifact a1 = TestArtifactBuilder.testArtifact()
                .groupId("org.apache.maven.plugins")
                .artifactId("maven-compiler-plugin")
                .packaging("jar")
                .version("1.0")
                .build();

        final Artifact a2 = TestArtifactBuilder.testArtifact()
                .groupId("org.apache.commons")
                .artifactId("commons-io")
                .packaging("jar")
                .version("1.0")
                .build();

        final List<Artifact> artifacts = asList(a1, a2, null);

        Builder builder = new ValidationChecksum.Builder()
                .destination(checksumdirectory)
                .artifacts(artifacts);

        assertThatCode(builder::build)
                .isExactlyInstanceOf(NullPointerException.class);
    }

    @Test
    void testValidationChecksumBuilderChecksumArtifactsRepeatedly() {
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
    void testValidationChecksumBuilderChecksumArtifactsDeterministicOrder() {
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
    void testValidationChecksumBuilderChecksumArtifactsDisabled() {
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
