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

import java.util.Optional;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.simplify4u.plugins.utils.PublicKeyUtils;

public class KeyInfoItemKey implements KeyInfoItem {

    private final byte[] fingerPrint;

    public KeyInfoItemKey(String key) {
        fingerPrint = strKeyToBytes(key);
    }

    @Override
    public boolean isKeyMatch(PGPPublicKey pgpPublicKey, PGPPublicKeyRing pgpPublicKeyRing) {

        if (compareArrays(fingerPrint, pgpPublicKey.getFingerprint())) {
            return true;
        }

        Optional<PGPPublicKey> masterKey = PublicKeyUtils.getMasterKey(pgpPublicKey, pgpPublicKeyRing);
        return masterKey.filter(publicKey -> isKeyMatch(publicKey, pgpPublicKeyRing)).isPresent();
    }

    private static byte[] strKeyToBytes(String key) {
        byte[] bytes;

        try {
            bytes = Hex.decode(key.substring(2));
        } catch (DecoderException e) {
            throw new IllegalArgumentException("Malformed keyID hex string " + key, e);
        }

        if (bytes.length < 8 || bytes.length > 20) {
            throw new IllegalArgumentException(
                    String.format("Key length for = %s is %d bits, should be between 64 and 160 bits",
                            key, bytes.length * 8));
        }

        return bytes;
    }

    private static boolean compareArrays(byte[] keyBytes, byte[] fingerprint) {

        for (int i = 1; i <= keyBytes.length && i <= fingerprint.length; i++) {
            if (keyBytes[keyBytes.length - i] != fingerprint[fingerprint.length - i]) {
                return false;
            }
        }
        return true;
    }
}
