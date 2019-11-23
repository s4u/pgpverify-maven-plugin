package org.simplify4u.plugins.skipfilters;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class ScopeSkipperTest {

    @Test(expectedExceptions = NullPointerException.class)
    public void testConstructNullScopeFilter() {
        new ScopeSkipper(null);
    }

    @Test
    public void testConstructTestScopeFilter() {
        final ScopeSkipper filter = new ScopeSkipper(Artifact.SCOPE_TEST);
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "system", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "provided", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "compile", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "runtime", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "test", "jar", "classifier", null)));
    }

    @Test
    public void testConstructCompileScopeFilter() {
        final ScopeSkipper filter = new ScopeSkipper(Artifact.SCOPE_COMPILE);
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "system", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "provided", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "compile", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "runtime", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "test", "jar", "classifier", null)));
    }

    @Test
    public void testConstructRuntimeScopeFilter() {
        final ScopeSkipper filter = new ScopeSkipper(Artifact.SCOPE_RUNTIME);
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "system", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "provided", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "compile", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "runtime", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "test", "jar", "classifier", null)));
    }

    @Test
    public void testConstructCompileRuntimeScopeFilter() {
        final ScopeSkipper filter = new ScopeSkipper(Artifact.SCOPE_COMPILE_PLUS_RUNTIME);
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "system", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "provided", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "compile", "jar", "classifier", null)));
        assertFalse(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "runtime", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "test", "jar", "classifier", null)));
    }

    @Test
    public void testConstructInvalidScopeFilter() {
        final ScopeSkipper filter = new ScopeSkipper("invalid-scope");
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "system", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "provided", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "compile", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "runtime", "jar", "classifier", null)));
        assertTrue(filter.shouldSkipArtifact(new DefaultArtifact("a", "b", "1.0", "test", "jar", "classifier", null)));
    }
}