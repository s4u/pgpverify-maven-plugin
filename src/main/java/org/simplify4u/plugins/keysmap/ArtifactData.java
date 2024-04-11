/*
 * Copyright 2021 Slawomir Jaranowski
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

import java.util.Locale;

import lombok.Getter;
import lombok.ToString;
import org.apache.maven.artifact.Artifact;

/**
 * Store normalized data about artifact.
 *
 * Used for optimize search on large keysMap.
 *
 * @author Slawomir Jaranowski.
 */
@Getter
@ToString
class ArtifactData {

    private final String groupId;
    private final String artifactId;
    private final String type;
    private final String version;

    ArtifactData(Artifact artifact) {
        groupId = artifact.getGroupId().toLowerCase(Locale.US);
        artifactId = artifact.getArtifactId().toLowerCase(Locale.US);
        type = artifact.getType().toLowerCase(Locale.US);
        version = artifact.getBaseVersion().toLowerCase(Locale.US);
    }
}
