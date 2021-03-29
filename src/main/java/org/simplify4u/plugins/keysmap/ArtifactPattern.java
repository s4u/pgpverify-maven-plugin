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
package org.simplify4u.plugins.keysmap;

import java.util.Locale;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import lombok.EqualsAndHashCode;
import org.apache.maven.artifact.versioning.DefaultArtifactVersion;
import org.apache.maven.artifact.versioning.InvalidVersionSpecificationException;
import org.apache.maven.artifact.versioning.VersionRange;

/**
 * Store information about artifact definition from KeysMap file.
 *
 * @author Slawomir Jaranowski.
 */
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
class ArtifactPattern {

    private static final Pattern DOT_REPLACE = Pattern.compile("\\.");
    private static final Pattern STAR_REPLACE = Pattern.compile("\\*");
    private static final Pattern PACKAGING = Pattern.compile("^[a-zA-Z]+$");

    /**
     * Original pattern from keysMap. Used to compare if object is equal to another.
     */
    @EqualsAndHashCode.Include
    private final String pattern;

    private final Pattern groupIdPattern;
    private final Pattern artifactIdPattern;
    private final Pattern packagingPattern;
    private final Function<String, Boolean> versionMatch;

    public ArtifactPattern(String pattern) {

        this.pattern = pattern;
        String[] split = this.pattern.split(":");
        String groupId = split.length > 0 ? split[0].trim().toLowerCase(Locale.US) : "";
        String artifactId = split.length > 1 ? split[1].trim().toLowerCase(Locale.US) : "";

        String packaging = "";
        String version = "";

        if (split.length == 3) {
            String item = split[2].trim().toLowerCase(Locale.US);
            if (PACKAGING.matcher(item).matches()) {
                packaging = item;
            } else {
                version = item;
            }
        } else if (split.length == 4) {
            packaging = split[2].trim().toLowerCase(Locale.US);
            version = split[3].trim().toLowerCase(Locale.US);
        } else {
            packaging = "";
        }


        try {
            groupIdPattern = Pattern.compile(patternPrepare(groupId));
            artifactIdPattern = Pattern.compile(patternPrepare(artifactId));
            packagingPattern = Pattern.compile(patternPrepare(packaging));
            versionMatch = versionMatchPrepare(version);
        } catch (InvalidVersionSpecificationException | PatternSyntaxException e) {
            throw new IllegalArgumentException("Invalid artifact definition: " + pattern, e);
        }
    }

    private static String patternPrepare(String str) {

        if (str.length() == 0) {
            return ".*";
        }

        String ret;
        if (str.endsWith(".*")) {
            ret = str.substring(0, str.length() - 2) + "(\\..+)?$";
        } else {
            ret = DOT_REPLACE.matcher(str).replaceAll("\\\\.");
            ret = STAR_REPLACE.matcher(ret).replaceAll(".*");
        }
        return ret;
    }

    private static Function<String, Boolean> versionMatchPrepare(String versionToPrepare)
            throws InvalidVersionSpecificationException {

        String versionSpec = versionSpecPrepare(versionToPrepare);

        if (versionSpec == null) {
            // special case - always true - the most common case
            // fix for https://github.com/s4u/pgpverify-maven-plugin/issues/135
            return version -> true;
        }

        VersionRange versionRange = VersionRange.createFromVersionSpec(versionSpec);
        if (versionRange.hasRestrictions()) {
            // check version in range
            return version -> {
                DefaultArtifactVersion artifactVersion = new DefaultArtifactVersion(version);
                return versionRange.containsVersion(artifactVersion);
            };
        } else {
            // only specific version to compare
            return versionSpec::equals;
        }
    }

    private static String versionSpecPrepare(String versionSpec) throws InvalidVersionSpecificationException {

        if (versionSpec.length() == 0 || "*".equals(versionSpec)) {
            // any version
            return null;
        }

        if (versionSpec.contains("*")) {
            throw new InvalidVersionSpecificationException("Invalid maven version range: " + versionSpec);
        }

        return versionSpec;
    }

    public boolean isMatch(ArtifactData artifact) {

        return isMatchPattern(groupIdPattern, artifact.getGroupId())
                && isMatchPattern(artifactIdPattern, artifact.getArtifactId())
                && isMatchPattern(packagingPattern, artifact.getType())
                && versionMatch.apply(artifact.getVersion());
    }

    private static boolean isMatchPattern(Pattern pattern, String str) {
        Matcher m = pattern.matcher(str);
        return m.matches();
    }
}
