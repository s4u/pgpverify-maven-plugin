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
import org.codehaus.plexus.util.StringUtils;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Slawomir Jaranowski.
 */
public class ArtifactInfo {

    private final String groupId;
    private final String artifactId;
    private final String type;

    public ArtifactInfo(String strArtifact) {

        String[] split = strArtifact.split(":");
        this.groupId = split.length > 0 ? split[0].trim().toLowerCase(Locale.US) : "";
        this.artifactId = split.length > 1 ? split[1].trim().toLowerCase(Locale.US) : "";
        this.type = split.length > 2 ? split[2].trim().toLowerCase(Locale.US) : "";
    }

    public ArtifactInfo(Artifact artifact) {
        this(artifact.getGroupId() + ":" + artifact.getArtifactId());
    }

    public boolean isMatch(Artifact artifact) {
        return Objects.equals(groupId, artifact.getGroupId()) &&
                Objects.equals(artifactId, artifact.getArtifactId()) &&
                Objects.equals(type, artifact.getType());
    }

    public String toString() {
        return new StringJoiner(":")
                .add(groupId)
                .add(artifactId)
                .toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ArtifactInfo that = (ArtifactInfo) o;
        return Objects.equals(groupId, that.groupId) &&
                Objects.equals(artifactId, that.artifactId) &&
                Objects.equals(type, that.type);
    }

    @Override
    public int hashCode() {
        return Objects.hash(groupId, artifactId, type);
    }
}
