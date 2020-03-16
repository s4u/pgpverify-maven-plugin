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
package org.simplify4u.plugins;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;

/**
 * Maven artifact builder for test purpose.
 */
public class TestArtifactBuilder {

    private String groupId = "test.group";
    private String artifactId = "test";
    private String packaging = "jar";
    private String version = "1.1.1" ;

    public static TestArtifactBuilder testArtifact() {
        return new TestArtifactBuilder();
    }

    public TestArtifactBuilder groupId(String groupId) {
        this.groupId = groupId;
        return this;
    }

    public TestArtifactBuilder artifactId(String artifactId) {
        this.artifactId = artifactId;
        return this;
    }

    public TestArtifactBuilder packaging(String packaging) {
        this.packaging = packaging;
        return this;
    }

    public TestArtifactBuilder version(String version) {
        this.version = version;
        return this;
    }

    public Artifact build() {
        return new DefaultArtifact(groupId, artifactId, version, "", packaging, "", null);
    }
}
