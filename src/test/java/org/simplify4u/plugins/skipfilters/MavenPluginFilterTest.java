/*
 * Copyright 2019 Danny van Heumen
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

import org.apache.maven.artifact.DefaultArtifact;
import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

@SuppressWarnings("ConstantConditions")
public class MavenPluginFilterTest {

    @Test(expectedExceptions = NullPointerException.class)
    public void testNullArtifact() {
        final MavenPluginFilter filter = new MavenPluginFilter();
        filter.shouldSkipArtifact(null);
    }

    @Test
    public void testNonPluginArtifact() {
        final MavenPluginFilter filter = new MavenPluginFilter();
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("abc", "def", "1.2.0", "compile", "jar", "classifier", null)));
    }

    @Test
    public void testPluginArtifact() {
        final MavenPluginFilter filter = new MavenPluginFilter();
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("abc", "def", "1.2.0", "compile", "maven-plugin", "classifier", null)));
    }

    @Test
    public void testNonPluginPOMArtifact() {
        final MavenPluginFilter filter = new MavenPluginFilter();
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("abc", "def", "1.2.0", "compile", "pom", "classifier", null)));
    }

    @Test
    public void testNonPluginRuntimeArtifact() {
        final MavenPluginFilter filter = new MavenPluginFilter();
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("abc", "def", "1.2.0", "runtime", "pom", "classifier", null)));
    }

    @Test
    public void testNonPluginSystemArtifact() {
        final MavenPluginFilter filter = new MavenPluginFilter();
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("abc", "def", "1.2.0", "test", "pom", "classifier", null)));
    }
}