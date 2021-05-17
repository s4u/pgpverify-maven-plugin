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
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.simplify4u.plugins.pgp.PublicKeyUtils;
import org.simplify4u.plugins.utils.HexUtils;

/**
 * Represent key as fingerprint for given artifact pattern.
 */
@EqualsAndHashCode
class KeyItemFingerprint implements KeyItem {

    private final byte[] fingerPrint;

    public KeyItemFingerprint(String key) {
        fingerPrint = stringToFingerprint(key);
    }

    @Override
    public boolean isKeyMatch(PGPPublicKey pgpPublicKey, PGPPublicKeyRing pgpPublicKeyRing) {

        if (compareArrays(fingerPrint, pgpPublicKey.getFingerprint())) {
            return true;
        }

        Optional<PGPPublicKey> masterKey = PublicKeyUtils.getMasterKey(pgpPublicKey, pgpPublicKeyRing);
        return masterKey.filter(publicKey -> isKeyMatch(publicKey, pgpPublicKeyRing)).isPresent();
    }

    private static boolean compareArrays(byte[] keyBytes, byte[] fingerprint) {

        for (int i = 1; i <= keyBytes.length && i <= fingerprint.length; i++) {
            if (keyBytes[keyBytes.length - i] != fingerprint[fingerprint.length - i]) {
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
