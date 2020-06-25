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
package org.simplify4u.plugins.utils;

import static org.simplify4u.plugins.utils.HexUtils.fingerprintToString;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;

public interface PGPKeyId {

    String getHashPath();

    PGPPublicKey getKeyFromRing(PGPPublicKeyRing publicKeyRing);

    PGPPublicKeyRing getKeyRingFromRingCollection(PGPPublicKeyRingCollection pgpRingCollection) throws PGPException;

    class PGPKeyIdLong implements PGPKeyId {

        private final Long keyId;

        PGPKeyIdLong(Long keyId) {
            this.keyId = keyId;
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
        public PGPPublicKeyRing getKeyRingFromRingCollection(PGPPublicKeyRingCollection pgpRingCollection)
                throws PGPException {
            return pgpRingCollection.getPublicKeyRing(keyId);
        }

        @Override
        public String toString() {
            return String.format("0x%016X", keyId);
        }
    }

    class PGPKeyIdFingerprint implements PGPKeyId {

        private final byte[] fingerprint;

        PGPKeyIdFingerprint(byte[] fingerprint) {
            this.fingerprint = fingerprint;
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
        public PGPPublicKeyRing getKeyRingFromRingCollection(PGPPublicKeyRingCollection pgpRingCollection)
                throws PGPException {
            return pgpRingCollection.getPublicKeyRing(fingerprint);
        }

        public String toString() {
            return fingerprintToString(fingerprint);
        }

    }

    static PGPKeyId from(byte[] fingerprint) {
        return new PGPKeyIdFingerprint(fingerprint);
    }

    static PGPKeyId from(Long keyId) {
        return new PGPKeyIdLong(keyId);
    }
}
