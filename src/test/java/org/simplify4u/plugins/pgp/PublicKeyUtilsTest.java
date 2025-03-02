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

import java.io.IOException;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.simplify4u.plugins.TestUtils.aKeyInfo;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.Test;

class PublicKeyUtilsTest {

    private static final KeyId SUB_KEY_ID = KeyId.from(0xEFE8086F9E93774EL);
    private static final long MASTER_KEY_ID = 0x164BD2247B936711L;

    private PGPPublicKeyRing loadKeyRing() throws IOException, PGPException {

        try (InputStream inputStream = getClass().getResourceAsStream("/EFE8086F9E93774E.asc")) {
            PublicKeyRingPack aPublicKeyRing = PublicKeyUtils.loadPublicKeyRing(inputStream, SUB_KEY_ID);
            assertThat(aPublicKeyRing.isEmpty()).isFalse();
            return aPublicKeyRing.getPublicKeyRing();
        }
    }

    @Test
    void fingerPrintForMasterKey() {

        KeyInfo keyInfo = KeyInfo.builder()
                .fingerprint(new KeyFingerprint("0x58E79B6ABC762159DC0B1591164BD2247B936711"))
                .build();

        assertThat(keyInfo.getMaster()).isNull();
        assertThat(PublicKeyUtils.fingerprintForMaster(keyInfo))
                .isEqualTo("0x58E79B6ABC762159DC0B1591164BD2247B936711");
    }

    @Test
    void fingerPrintForSubKey() {
        KeyInfo keyInfo = KeyInfo.builder()
                .fingerprint(new KeyFingerprint("0x1234567890123456789012345678901234567890"))
                .master(new KeyFingerprint("0x58E79B6ABC762159DC0B1591164BD2247B936711"))
                .build();

        assertThat(keyInfo.getMaster()).isNotNull();
        assertThat(PublicKeyUtils.fingerprintForMaster(keyInfo))
                .isEqualTo("0x58E79B6ABC762159DC0B1591164BD2247B936711");
    }

    @Test
    void userIdsWithSubKey() throws Exception {

        PGPPublicKeyRing publicKeyRing = loadKeyRing();
        PGPPublicKey key = SUB_KEY_ID.getKeyFromRing(publicKeyRing);

        assertThat(key.isMasterKey()).isFalse();
        assertThat(PublicKeyUtils.getUserIDs(key, publicKeyRing))
                .containsOnly("Marc Philipp (JUnit Development, 2014) <mail@marcphilipp.de>");
    }

    @Test
    void userIdsWithMasterKey() throws Exception {
        PGPPublicKeyRing publicKeyRing = loadKeyRing();
        PGPPublicKey key = publicKeyRing.getPublicKey(MASTER_KEY_ID);

        assertThat(key.isMasterKey()).isTrue();
        assertThat(PublicKeyUtils.getUserIDs(key, publicKeyRing))
                .containsOnly("Marc Philipp (JUnit Development, 2014) <mail@marcphilipp.de>");
    }

    @Test
    void keyIdDescriptionForMasterKey() {

        KeyInfo keyInfo = aKeyInfo("0x1234567890123456789012345678901234567890");

        assertThat(keyInfo.getMaster()).isNull();
        assertThat(PublicKeyUtils.keyIdDescription(keyInfo))
                .isEqualTo("KeyId: 0x1234567890123456789012345678901234567890");
    }

    @Test
    void keyIdDescriptionForSubKey() {
        KeyInfo keyInfo = aKeyInfo("0x0987654321098765432109876543210987654321", "0x1234567890123456789012345678901234567890");

        assertThat(keyInfo.getMaster()).isNotNull();
        assertThat(PublicKeyUtils.keyIdDescription(keyInfo))
                .isEqualTo("SubKeyId: 0x0987654321098765432109876543210987654321 of 0x1234567890123456789012345678901234567890");
    }

    @Test
    void invalidUTF8InUserId() throws IOException, PGPException {

        try (InputStream inputStream = getClass().getResourceAsStream("/B0F3710FA64900E7.asc")) {
            PublicKeyRingPack keyRingPack = PublicKeyUtils.loadPublicKeyRing(inputStream, KeyId.from(0xB0F3710FA64900E7L));

            assertThat(keyRingPack.hasPublicKeys()).isTrue();
            PGPPublicKeyRing publicKeyRing = keyRingPack.getPublicKeyRing();
            assertThat(PublicKeyUtils.getUserIDs(publicKeyRing.getPublicKey(0xB0F3710FA64900E7L), publicKeyRing))
                    .containsOnly("�amonn McManus <eamonn@mcmanus.net>");
        }
    }

    @Test
    void validateSubKeyWithExternalSignature() throws IOException, PGPException {

        try (InputStream inputStream = getClass().getResourceAsStream("/3D8B00E198E21827.asc")) {
            PublicKeyRingPack keyRingPack = PublicKeyUtils.loadPublicKeyRing(inputStream, KeyId.from(0x3D8B00E198E21827L));

            assertThat(keyRingPack.hasPublicKeys()).isTrue();
            PGPPublicKeyRing publicKeyRing = keyRingPack.getPublicKeyRing();
            assertThat(PublicKeyUtils.getUserIDs(publicKeyRing.getPublicKey(0x3D8B00E198E21827L), publicKeyRing))
                    .containsOnly("Rick Hillegas <rhillegas@apache.org>");
        }
    }

    @Test
    void validateSubKeyWithRevokedSignature() throws IOException, PGPException {

        try (InputStream inputStream = getClass().getResourceAsStream("/411063A3A0FFD119.asc")) {
            PublicKeyRingPack keyRingPack = PublicKeyUtils.loadPublicKeyRing(inputStream, KeyId.from(0x411063A3A0FFD119L));

            assertThat(keyRingPack.hasPublicKeys()).isTrue();
            PGPPublicKeyRing publicKeyRing = keyRingPack.getPublicKeyRing();
            assertThat(PublicKeyUtils.getUserIDs(publicKeyRing.getPublicKey(0x411063A3A0FFD119L), publicKeyRing))
                    .hasSize(17)
                    .contains("Stian Soiland <stain@stud.ntnu.no>");
        }
    }

    @Test
    void onlyRevokedSignature() throws IOException, PGPException {
        try (InputStream inputStream = getClass().getResourceAsStream("/D0BF1D737C9A1C22.asc")) {
            PublicKeyRingPack keyRingPack = PublicKeyUtils.loadPublicKeyRing(inputStream, KeyId.from(0xD0BF1D737C9A1C22L));

            assertThat(keyRingPack.isEmpty()).isFalse();
            assertThat(keyRingPack.hasPublicKeys()).isFalse();
            assertThat(keyRingPack.getRevocationSignature()).isNotNull();
        }
    }
}
