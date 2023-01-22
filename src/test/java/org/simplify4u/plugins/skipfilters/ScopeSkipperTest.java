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

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ScopeSkipperTest {

    @Test
    void testConstructNullScopeFilter() {
        assertThrows(NullPointerException.class, () -> new ScopeSkipper(null));
    }

    @Test
    void testConstructTestScopeFilter() {
        final ScopeSkipper filter = new ScopeSkipper(Artifact.SCOPE_TEST);
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "system", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "provided", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "compile", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "runtime", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "test", "jar", "classifier", null)));
    }

    @Test
    void testConstructCompileScopeFilter() {
        final ScopeSkipper filter = new ScopeSkipper(Artifact.SCOPE_COMPILE);
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "system", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "provided", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "compile", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "runtime", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "test", "jar", "classifier", null)));
    }

    @Test
    void testConstructRuntimeScopeFilter() {
        final ScopeSkipper filter = new ScopeSkipper(Artifact.SCOPE_RUNTIME);
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "system", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "provided", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "compile", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "runtime", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "test", "jar", "classifier", null)));
    }

    @Test
    void testConstructCompileRuntimeScopeFilter() {
        final ScopeSkipper filter = new ScopeSkipper(Artifact.SCOPE_COMPILE_PLUS_RUNTIME);
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "system", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "provided", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "compile", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "runtime", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "test", "jar", "classifier", null)));
    }

    @Test
    void testConstructInvalidScopeFilter() {
        final ScopeSkipper filter = new ScopeSkipper("invalid-scope");
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "system", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "provided", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "compile", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "runtime", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "test", "jar", "classifier", null)));
    }
}