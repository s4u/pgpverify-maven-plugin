/*
 * Copyright 2020-2021 Slawomir Jaranowski
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
package org.simplify4u.plugins.pgp;

import java.math.BigInteger;
import java.util.Arrays;

import static org.simplify4u.plugins.utils.HexUtils.fingerprintToString;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.EqualsAndHashCode;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

/**
 * KeyId representation.
 */
public interface KeyId {

    long getId();

    String getHashPath();

    PGPPublicKey getKeyFromRing(PGPPublicKeyRing publicKeyRing);

    /**
     * Representation of a keyId with long as key.
     */
    @EqualsAndHashCode
    class KeyIdLong implements KeyId {

        private final Long keyId;

        KeyIdLong(Long keyId) {
            this.keyId = keyId;
        }

        @Override
        public long getId() {
            return keyId;
        }

        @Override
        public String getHashPath() {
            return String.format("%02X/%02X/%016X.asc", (byte) (keyId >> 56), (byte) (keyId >> 48 & 0xff), keyId);
        }

        @Override
        public PGPPublicKey getKeyFromRing(PGPPublicKeyRing publicKeyRing) {
            return publicKeyRing.getPublicKey(keyId);
        }

        @Override
        @JsonValue
        public String toString() {
            return String.format("0x%016X", keyId);
        }
    }

    /**
     * Representation of a keyId with fingerprint as key.
     */
    @EqualsAndHashCode
    class KeyIdFingerprint implements KeyId {

        private final byte[] fingerprint;

        KeyIdFingerprint(byte[] fingerprint) {
            this.fingerprint = fingerprint;
        }

        @Override
        public long getId() {
            return new BigInteger(Arrays.copyOfRange(fingerprint, fingerprint.length - 8, fingerprint.length)).
                    longValue();
        }

        @Override
        public String getHashPath() {
            StringBuilder ret = new StringBuilder();
            ret.append(String.format("%02X/", fingerprint[0]));
            ret.append(String.format("%02X/", fingerprint[1]));
            for (byte b: fingerprint) {
                ret.append(String.format("%02X", b));
            }
            ret.append(".asc");
            return ret.toString();
        }

        @Override
        public PGPPublicKey getKeyFromRing(PGPPublicKeyRing publicKeyRing) {
            return publicKeyRing.getPublicKey(fingerprint);
        }

        @Override
        @JsonValue
        public String toString() {
            return fingerprintToString(fingerprint);
        }

    }

    static KeyId from(byte[] fingerprint) {
        return new KeyIdFingerprint(fingerprint);
    }

    static KeyId from(Long keyId) {
        return new KeyIdLong(keyId);
    }
}
