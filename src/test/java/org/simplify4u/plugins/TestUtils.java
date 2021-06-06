/*
 * Copyright 2017-2021 Slawomir Jaranowski
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

import java.util.Collections;
import java.util.Date;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.simplify4u.plugins.keysmap.KeysMapLocationConfig;
import org.simplify4u.plugins.pgp.ArtifactInfo;
import org.simplify4u.plugins.pgp.KeyFingerprint;
import org.simplify4u.plugins.pgp.KeyId;
import org.simplify4u.plugins.pgp.KeyInfo;
import org.simplify4u.plugins.pgp.SignatureCheckResult;
import org.simplify4u.plugins.pgp.SignatureInfo;
import org.simplify4u.plugins.pgp.SignatureStatus;

/**
 * @author Slawomir Jaranowski.
 */
public final class TestUtils {

    public static KeysMapLocationConfig aKeysMapLocationConfig(String location) {
        KeysMapLocationConfig config = new KeysMapLocationConfig();
        config.set(location);
        return config;
    }

    public static KeyInfo aKeyInfo(String fingerprint) {
        return KeyInfo.builder().fingerprint(new KeyFingerprint(fingerprint)).build();
    }

    public static KeyInfo aKeyInfo(String fingerprint, String masterFingerprint) {
        return KeyInfo.builder()
                .fingerprint(new KeyFingerprint(fingerprint))
                .master(new KeyFingerprint(masterFingerprint))
                .build();
    }

    public static SignatureCheckResult.SignatureCheckResultBuilder aSignatureCheckResultBuilder(Date date) {
        return SignatureCheckResult.builder()
                .artifact(ArtifactInfo.builder()
                        .groupId("groupId")
                        .artifactId("artifactId")
                        .type("jar")
                        .classifier("classifier")
                        .version("1.0")
                        .build())
                .signature(SignatureInfo.builder()
                        .version(4)
                        .keyId(KeyId.from(0x1234L))
                        .hashAlgorithm(HashAlgorithmTags.MD5)
                        .keyAlgorithm(PublicKeyAlgorithmTags.RSA_GENERAL)
                        .date(date)
                        .build())
                .key(KeyInfo.builder()
                        .version(4)
                        .fingerprint(new KeyFingerprint("0x12345678901234567890"))
                        .master(new KeyFingerprint("0x09876543210987654321"))
                        .algorithm(PublicKeyAlgorithmTags.RSA_GENERAL)
                        .uids(Collections.singleton("Test uid <uid@example.com>"))
                        .bits(2048)
                        .date(date)
                        .build())
                .status(SignatureStatus.SIGNATURE_VALID)
                .keyShowUrl("https://example.com/key");
    }

    public static SignatureCheckResult.SignatureCheckResultBuilder aSignatureCheckResultBuilder() {
        return aSignatureCheckResultBuilder(new Date());
    }
}
