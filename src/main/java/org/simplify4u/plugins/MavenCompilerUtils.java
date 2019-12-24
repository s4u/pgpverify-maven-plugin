package org.simplify4u.plugins;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.model.Plugin;
import org.apache.maven.repository.RepositorySystem;
import org.codehaus.plexus.util.xml.Xpp3Dom;

import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;
import static java.util.Collections.emptySet;
import static java.util.Objects.requireNonNull;

/**
 * Utilities specific for org.apache.maven.plugins:maven-compiler-plugin.
 */
final class MavenCompilerUtils {

    private static final String GROUPID = "org.apache.maven.plugins";
    private static final String ARTIFACTID = "maven-compiler-plugin";

    private static final String PACKAGING = "jar";

    private MavenCompilerUtils() {
        // No need to instantiate utility class.
    }

    /**
     * Check if provided plugin is org.apache.maven.plugins:maven-compiler-plugin.
     *
     * @param plugin any plugin instance
     * @return Returns true iff plugin is maven-compiler-plugin.
     */
    static boolean checkCompilerPlugin(Plugin plugin) {
        return GROUPID.equals(plugin.getGroupId()) && ARTIFACTID.equals(plugin.getArtifactId());
    }

    /**
     * Extract annotation processors for maven-compiler-plugin configuration.
     *
     * @param system maven repository system
     * @param plugin maven-compiler-plugin plugin
     * @return Returns set of maven artifacts configured as annotation processors.
     */
    static Set<Artifact> extractAnnotationProcessors(RepositorySystem system, Plugin plugin) {
        requireNonNull(system);
        if (!checkCompilerPlugin(plugin)) {
            throw new IllegalArgumentException("Plugin is not '" + GROUPID + ":" + ARTIFACTID + "'.");
        }
        final Object config = plugin.getConfiguration();
        if (config == null) {
            return emptySet();
        }
        if (config instanceof Xpp3Dom) {
            return stream(((Xpp3Dom) config).getChildren("annotationProcessorPaths"))
                    .flatMap(aggregate -> stream(aggregate.getChildren("path")))
                    .map(processor -> system.createArtifact(
                            extractChildValue(processor, "groupId"),
                            extractChildValue(processor, "artifactId"),
                            extractChildValue(processor, "version"),
                            PACKAGING))
                    // A path specification is automatically ignored in maven-compiler-plugin if version is absent,
                    // therefore there is little use in logging incomplete paths that are filtered out.
                    .filter(a -> !a.getGroupId().isEmpty())
                    .filter(a -> !a.getArtifactId().isEmpty())
                    .filter(a -> !a.getVersion().isEmpty())
                    .collect(Collectors.toSet());
        }
        // It is expected that this will never occur due to all Configuration instances of all plugins being provided as
        // XML document. If this happens to occur on very old plugin versions, we can safely add the type support and
        // simply return an empty set.
        throw new UnsupportedOperationException("Please report that an unsupported type of configuration container was encountered: "
                + config.getClass());
    }

    /**
     * Extract child value if child is present, or return empty string if absent.
     *
     * @param node the parent node
     * @param name the child node name
     * @return Returns child value if child node present or otherwise empty string.
     */
    private static String extractChildValue(Xpp3Dom node, String name) {
        final Xpp3Dom child = node.getChild(name);
        return child == null ? "" : child.getValue();
    }
}
