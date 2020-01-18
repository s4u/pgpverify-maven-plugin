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

import java.math.BigInteger;
import java.util.Arrays;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.bouncycastle.openpgp.PGPPublicKey;

/**
 * @author Slawomir Jaranowski.
 */
public abstract class TestUtils {

    static Artifact getArtifact(String groupId, String artifactId, String version) {
        return new DefaultArtifact(groupId, artifactId, version, "", "", "", null);
    }

    static PGPPublicKey getPGPgpPublicKey(long keyID) {

        BigInteger bigInteger = BigInteger.valueOf(0xffffffffL & keyID);
        BigInteger bigInteger2 = BigInteger.valueOf(keyID);

        bigInteger = bigInteger.shiftLeft(64);
        bigInteger = bigInteger.or(bigInteger2);

        bigInteger = bigInteger.shiftLeft(64);
        bigInteger = bigInteger.or(bigInteger2);

        byte[] bytes = bigInteger.toByteArray();
        if (bytes[0] == 0) {
            // we can remove sign byte
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }

        PGPPublicKey pgpKey = mock(PGPPublicKey.class);
        when(pgpKey.getFingerprint()).thenReturn(bytes);
        when(pgpKey.isMasterKey()).thenReturn(true);

        return pgpKey;
    }
}
