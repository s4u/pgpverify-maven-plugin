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

import org.simplify4u.plugins.keysmap.KeysMapLocationConfig;
import org.simplify4u.plugins.pgp.KeyFingerprint;
import org.simplify4u.plugins.pgp.KeyInfo;

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

}
