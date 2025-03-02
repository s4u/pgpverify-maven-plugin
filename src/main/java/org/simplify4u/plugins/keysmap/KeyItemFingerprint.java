/*
 * Copyright 2021 Slawomir Jaranowski
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

import java.util.Optional;

import static org.simplify4u.plugins.utils.HexUtils.stringToFingerprint;

import lombok.EqualsAndHashCode;
import org.simplify4u.plugins.pgp.KeyFingerprint;
import org.simplify4u.plugins.pgp.KeyInfo;
import org.simplify4u.plugins.utils.HexUtils;

/**
 * Represent key as fingerprint for given artifact pattern.
 */
@EqualsAndHashCode
class KeyItemFingerprint implements KeyItem {

    private final boolean allowNoPublicKey;
    private final byte[] fingerPrint;

    public KeyItemFingerprint(String key) {
        if (key.startsWith("!")) {
            fingerPrint = stringToFingerprint(key.substring(1));
            allowNoPublicKey = true;
        } else {
            fingerPrint = stringToFingerprint(key);
            allowNoPublicKey = false;
        }
    }

    @Override
    public boolean isKeyMatch(KeyInfo keyInfo) {
        return !allowNoPublicKey && compareWith(keyInfo);
    }

    @Override
    public boolean isKeyMatchNoPublicKey(KeyInfo keyInfo) {
        return allowNoPublicKey && compareWith(keyInfo);
    }

    private boolean compareWith(KeyInfo keyInfo) {
        return compareWith(keyInfo.getMaster()) || compareWith(keyInfo.getFingerprint()) ;
    }

    private boolean compareWith(KeyFingerprint fingerprint) {
        return Optional.ofNullable(fingerprint)
                .map(KeyFingerprint::getFingerprint)
                .map(this::compareWith)
                .orElse(false);
    }

    private boolean compareWith(byte[] keyBytes) {
        for (int i = 1; i <= fingerPrint.length && i <= keyBytes.length; i++) {
            if (fingerPrint[fingerPrint.length - i] != keyBytes[keyBytes.length - i]) {
                return false;
            }
        }
        return true;
    }

    @Override
    public String toString() {
        return HexUtils.fingerprintToString(fingerPrint);
    }
}
