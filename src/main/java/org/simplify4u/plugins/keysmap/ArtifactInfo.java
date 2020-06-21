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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.versioning.DefaultArtifactVersion;
import org.apache.maven.artifact.versioning.InvalidVersionSpecificationException;
import org.apache.maven.artifact.versioning.VersionRange;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

/**
 * Store information about artifact definition from KeysMap file.
 *
 * @author Slawomir Jaranowski.
 */
class ArtifactInfo {

    private final KeyInfo keyInfo;

    private final Pattern groupIdPattern;
    private final Pattern artifactIdPattern;
    private final Pattern packagingPattern;
    private final VersionRange versionRange;

    private static final Pattern DOT_REPLACE = Pattern.compile("\\.");
    private static final Pattern STAR_REPLACE = Pattern.compile("\\*");
    private static final Pattern PACKAGING = Pattern.compile("^[a-zA-Z]+$");

    public ArtifactInfo(String strArtifact, KeyInfo keyInfo) {

        String[] split = strArtifact.split(":");
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
            versionRange = VersionRange.createFromVersionSpec(versionSpecPrepare(version));
        } catch (InvalidVersionSpecificationException | PatternSyntaxException e) {
            throw new IllegalArgumentException("Invalid artifact definition: " + strArtifact, e);
        }
        this.keyInfo = keyInfo;
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

    private static String versionSpecPrepare(String versionSpec) throws InvalidVersionSpecificationException {

        if (versionSpec.length() == 0 || "*".equals(versionSpec)) {
            // any version
            return "[0.0.0,)";
        }

        if (versionSpec.contains("*")) {
            throw new InvalidVersionSpecificationException("Invalid maven version range: " + versionSpec);
        }

        return versionSpec;
    }

    public boolean isMatch(Artifact artifact) {

        return isMatchPattern(groupIdPattern, artifact.getGroupId())
                && isMatchPattern(artifactIdPattern, artifact.getArtifactId())
                && isMatchPattern(packagingPattern, artifact.getType())
                && isMatchVersion(artifact.getVersion());
    }

    private boolean isMatchVersion(String version) {

        DefaultArtifactVersion artifactVersion = new DefaultArtifactVersion(version);

        if (versionRange.hasRestrictions()) {
            return versionRange.containsVersion(artifactVersion);
        }

        return artifactVersion.equals(versionRange.getRecommendedVersion());
    }

    private static boolean isMatchPattern(Pattern pattern, String str) {
        Matcher m = pattern.matcher(str.toLowerCase(Locale.US));
        return m.matches();
    }

    public boolean isKeyMatch(PGPPublicKey key, PGPPublicKeyRing keyRing) {
        return keyInfo.isKeyMatch(key, keyRing);
    }

    public boolean isNoSignature() {
        return keyInfo.isNoSignature();
    }

    public boolean isBrokenSignature() {
        return keyInfo.isBrokenSignature();
    }

    public boolean isKeyMissing() {
        return keyInfo.isKeyMissing();
    }
}
