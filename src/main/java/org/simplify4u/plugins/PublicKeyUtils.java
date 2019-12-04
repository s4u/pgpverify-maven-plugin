/*
 * Copyright 2019 Slawomir Jaranowski
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

import org.bouncycastle.openpgp.PGPPublicKey;

/**
 * Utility for PGPPublicKey
 */
final class PublicKeyUtils {

    private PublicKeyUtils() {
        // No need to instantiate utility class.
    }

    /**
     * Generate string version of key fingerprint
     * @param publicKey given key
     * @return fingerprint as string
     */
    static String fingerprint(PGPPublicKey publicKey) {

        StringBuilder ret = new StringBuilder("0x");
        for (Byte b : publicKey.getFingerprint()) {
            ret.append(String.format("%02X", b));
        }
        return ret.toString();
    }
}
