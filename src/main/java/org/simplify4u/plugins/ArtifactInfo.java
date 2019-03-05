/*
 * Copyright 2017 Slawomir Jaranowski
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
package org.simplify4u.plugins;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.maven.artifact.Artifact;
import org.bouncycastle.openpgp.PGPPublicKey;

/**
 * @author Slawomir Jaranowski.
 */
public class ArtifactInfo {

    private final KeyInfo keyInfo;

    private final Pattern groupIdPattern;
    private final Pattern artifactIdPattern;
    private final Pattern versionPattern;

    private static final Pattern DOT_REPLACE = Pattern.compile("\\.");
    private static final Pattern STAR_REPLACE = Pattern.compile("\\*");

    public ArtifactInfo(String strArtifact, KeyInfo keyInfo) {

        String[] split = strArtifact.split(":");
        String groupId = split.length > 0 ? split[0].trim().toLowerCase(Locale.US) : "";
        String artifactId = split.length > 1 ? split[1].trim().toLowerCase(Locale.US) : "";
        String version = split.length > 2 ? split[2].trim().toLowerCase(Locale.US) : "";

        groupIdPattern = Pattern.compile(patternPrepare(groupId));
        artifactIdPattern = Pattern.compile(patternPrepare(artifactId));
        versionPattern = Pattern.compile(patternPrepare(version));

        this.keyInfo = keyInfo;
    }

    private String patternPrepare(String str) {

        if (str.length() == 0) {
            return ".*";
        }

        String ret = DOT_REPLACE.matcher(str).replaceAll("\\\\.");
        ret = STAR_REPLACE.matcher(ret).replaceAll(".*");
        return ret;
    }

    public boolean isMatch(Artifact artifact) {

        return isMatchPattern(groupIdPattern, artifact.getGroupId())
                && isMatchPattern(artifactIdPattern, artifact.getArtifactId())
                && isMatchPattern(versionPattern, artifact.getVersion());
    }

    private boolean isMatchPattern(Pattern pattern, String str) {
        Matcher m = pattern.matcher(str.toLowerCase(Locale.US));
        return m.matches();
    }

    public boolean isKeyMatch(PGPPublicKey key) {
        return keyInfo.isKeyMatch(key);
    }
}
