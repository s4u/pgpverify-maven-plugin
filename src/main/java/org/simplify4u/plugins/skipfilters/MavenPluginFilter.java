/*
 * Copyright 2019 Slawomir Jaranowski
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

package org.simplify4u.plugins.skipfilters;

import org.apache.maven.artifact.Artifact;

/**
 * A filter for skipping Maven build plug-ins.
 */
public class MavenPluginFilter implements SkipFilter {

    private static final String TYPE_MAVEN_PLUGIN = "maven-plugin";

    @Override
    public boolean shouldSkipArtifact(final Artifact artifact) {
        return TYPE_MAVEN_PLUGIN.equals(artifact.getType());
    }
}
