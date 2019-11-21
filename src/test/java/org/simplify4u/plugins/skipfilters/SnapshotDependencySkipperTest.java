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

import static org.testng.Assert.*;

@SuppressWarnings("ConstantConditions")
public class SnapshotDependencySkipperTest {

    @Test(expectedExceptions = NullPointerException.class)
    public void testNullArtifact() {
        final SnapshotDependencySkipper filter = new SnapshotDependencySkipper();
        filter.shouldSkipArtifact(null);
    }

    @Test
    public void testCompileArtifact() {
        final SnapshotDependencySkipper filter = new SnapshotDependencySkipper();
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("abc", "def", "1.0.0", "compile",
                "jar", "classifier", null)));
    }

    @Test
    public void testProvidedArtifact() {
        final SnapshotDependencySkipper filter = new SnapshotDependencySkipper();
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("abc", "def", "1.0.0-SNAPSHOT", "compile",
                "jar", "classifier", null)));
    }
}