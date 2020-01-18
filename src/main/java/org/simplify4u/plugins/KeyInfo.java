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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

/**
 * Store info about key number.
 *
 * @author Slawomir Jaranowski.
 */
public class KeyInfo {

    private final boolean matchAny;
    private final List<byte[]> keysID = new ArrayList<>();

    public KeyInfo(String strKeys) {

        if ("*".equals(strKeys) || "any".equalsIgnoreCase(strKeys)) {
            matchAny = true;
            return;
        } else {
            matchAny = false;
        }

        if (strKeys == null) {
            throw new IllegalArgumentException("null key not allowed");
        }

        if (strKeys.trim().isEmpty()) {
            return;
        }

        for (String key : strKeys.split(",")) {
            key = key.trim();
            if (key.startsWith("0x")) {
                byte[] bytes = strKeyToBytes(key.substring(2));
                keysID.add(bytes);
            } else {
                throw new IllegalArgumentException("Invalid keyID " + key + " must start with 0x");
            }
        }
    }

    private byte[] strKeyToBytes(String key) {

        BigInteger bigInteger = new BigInteger(key.replace(" ", ""), 16);

        byte[] bytes = bigInteger.toByteArray();

        if (bytes[0] == 0) {
            // we can remove sign byte
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }

        if (bytes.length < 8 || bytes.length > 20) {
            throw new IllegalArgumentException(
                    String.format("Key length for = 0x%s is %d bits, should be between 64 and 160 bits",
                            key, bytes.length * 8));
        }

        return bytes;
    }

    public boolean isKeyMatch(PGPPublicKey pgpPublicKey, PGPPublicKeyRing pgpPublicKeyRing) {

        if (matchAny) {
            return true;
        }

        byte[] fingerprint = pgpPublicKey.getFingerprint();

        for (byte[] keyBytes : keysID) {
            if (compareArrays(keyBytes, fingerprint)) {
                return true;
            }
        }

        Optional<PGPPublicKey> masterKey = PublicKeyUtils.getMasterKey(pgpPublicKey, pgpPublicKeyRing);
        if (masterKey.isPresent()) {
            return isKeyMatch(masterKey.get(), pgpPublicKeyRing);
        }

        return false;
    }

    private boolean compareArrays(byte[] keyBytes, byte[] fingerprint) {

        for (int i = 1; i <= keyBytes.length && i <= fingerprint.length; i++) {
            if (keyBytes[keyBytes.length - i] != fingerprint[fingerprint.length - i]) {
                return false;
            }
        }
        return true;
    }

    public boolean isNoKey() {
        return keysID.isEmpty();
    }
}
