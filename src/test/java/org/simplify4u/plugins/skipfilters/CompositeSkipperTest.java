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

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.testng.Assert.*;

public class CompositeSkipperTest {

    @Test
    public void testNullFilters() {
        assertThrows(NullPointerException.class, () -> new CompositeSkipper((Iterable<SkipFilter>) null));
        assertThrows(NullPointerException.class, () -> new CompositeSkipper((SkipFilter[]) null));
        assertThrows(IllegalArgumentException.class, () -> new CompositeSkipper((SkipFilter) null));
    }

    @Test(expectedExceptions = NullPointerException.class)
    public void testEmptyFiltersList() {
        final CompositeSkipper filter = new CompositeSkipper(emptyList());
        filter.shouldSkipArtifact(null);
    }

    @Test
    public void testActualArtifactEmptyFiltersList() {
        final DefaultArtifact artifact = new DefaultArtifact("abc", "def", "1.2.0", "compile",
                "jar", "some-classifier", null);
        final CompositeSkipper filter = new CompositeSkipper(emptyList());
        assertFalse(filter.shouldSkipArtifact(artifact));
    }

    @Test
    public void testCompileScopedArtifactProvidedScopeFilter() {
        final DefaultArtifact artifact = new DefaultArtifact("abc", "def", "1.2.0", "compile",
                "jar", "some-classifier", null);
        final CompositeSkipper filter = new CompositeSkipper(singletonList(new ProvidedDependencySkipper()));
        assertFalse(filter.shouldSkipArtifact(artifact));
    }

    @Test
    public void testProvidedScopedArtifactProvidedScopeFilter() {
        final DefaultArtifact artifact = new DefaultArtifact("abc", "def", "1.2.0", "provided",
                "jar", "some-classifier", null);
        final CompositeSkipper filter = new CompositeSkipper(singletonList(new ProvidedDependencySkipper()));
        assertTrue(filter.shouldSkipArtifact(artifact));
    }

    @Test
    public void testProvidedScopedArtifactMultipleFilters() {
        final CompositeSkipper filter = new CompositeSkipper(asList(
                new ProvidedDependencySkipper(), new SnapshotDependencySkipper()));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("abc", "def", "1.2.0", "provided",
                "jar", "some-classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("abc", "def", "1.2.0-SNAPSHOT", "compile",
                "jar", "some-classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("abc", "def", "1.0.0", "compile",
                "jar", "some-classifier", null)));
    }
}