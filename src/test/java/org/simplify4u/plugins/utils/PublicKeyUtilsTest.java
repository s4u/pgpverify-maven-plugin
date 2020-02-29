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

import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class PublicKeyUtilsTest {

    private static final long SUB_KEY_ID = 0xEFE8086F9E93774EL;
    private static final long MASTER_KEY_ID = 0x164BD2247B936711L;

    private PGPPublicKeyRing publicKeyRing;

    @BeforeClass
    public void loadKeyRing() throws IOException, PGPException {

        try (InputStream inputStream = getClass().getResourceAsStream("/EFE8086F9E93774E.asc")) {
            Optional<PGPPublicKeyRing> aPublicKeyRing = PublicKeyUtils.loadPublicKeyRing(inputStream, SUB_KEY_ID);
            assertThat(aPublicKeyRing)
                    .hasValueSatisfying(publicKeyRing -> assertThat(publicKeyRing).isNotEmpty());

            publicKeyRing = aPublicKeyRing.get();
        }
    }


    @Test
    public void fingerPrintForMasterWithSubKey() {

        PGPPublicKey key = publicKeyRing.getPublicKey(SUB_KEY_ID);

        assertThat(key.isMasterKey()).isFalse();
        assertThat(PublicKeyUtils.fingerprintForMaster(key, publicKeyRing))
                .isEqualTo("0x58E79B6ABC762159DC0B1591164BD2247B936711");
    }

    @Test
    public void fingerPrintForMasterWithMasterKey() throws IOException, PGPException {

        PGPPublicKey key = publicKeyRing.getPublicKey(MASTER_KEY_ID);

        assertThat(key.isMasterKey()).isTrue();
        assertThat(PublicKeyUtils.fingerprintForMaster(key, publicKeyRing))
                .isEqualTo("0x58E79B6ABC762159DC0B1591164BD2247B936711");
    }

    @Test
    public void userIdsWithSubKey() throws IOException, PGPException {

        PGPPublicKey key = publicKeyRing.getPublicKey(SUB_KEY_ID);

        assertThat(key.isMasterKey()).isFalse();
        assertThat(PublicKeyUtils.getUserIDs(key, publicKeyRing))
                .containsOnly("Marc Philipp (JUnit Development, 2014) <mail@marcphilipp.de>");
    }

    @Test
    public void userIdsWithMasterKey() throws IOException, PGPException {

        PGPPublicKey key = publicKeyRing.getPublicKey(MASTER_KEY_ID);

        assertThat(key.isMasterKey()).isTrue();
        assertThat(PublicKeyUtils.getUserIDs(key, publicKeyRing))
                .containsOnly("Marc Philipp (JUnit Development, 2014) <mail@marcphilipp.de>");
    }

    @Test
    public void keyIdDescriptionForMasterKey() {

        PGPPublicKey key = publicKeyRing.getPublicKey(MASTER_KEY_ID);

        assertThat(key.isMasterKey()).isTrue();
        assertThat(PublicKeyUtils.keyIdDescription(key, publicKeyRing))
                .isEqualTo("KeyId: 0x58E79B6ABC762159DC0B1591164BD2247B936711");
    }

    @Test
    public void keyIdDescriptionForSubKey() {

        PGPPublicKey key = publicKeyRing.getPublicKey(SUB_KEY_ID);

        assertThat(key.isMasterKey()).isFalse();
        assertThat(PublicKeyUtils.keyIdDescription(key, publicKeyRing))
                .isEqualTo("SubKeyId: 0xEFE8086F9E93774E of 0x58E79B6ABC762159DC0B1591164BD2247B936711");
    }

    @Test
    public void invalidUTF8InUserId() throws IOException, PGPException {

        try (InputStream inputStream = getClass().getResourceAsStream("/B0F3710FA64900E7.asc")) {
            Optional<PGPPublicKeyRing> aPublicKeyRing = PublicKeyUtils.loadPublicKeyRing(inputStream, 0xB0F3710FA64900E7L);

            assertThat(aPublicKeyRing)
                    .hasValueSatisfying(publicKeyRing ->
                            assertThat(PublicKeyUtils.getUserIDs(publicKeyRing.getPublicKey(0xB0F3710FA64900E7L), publicKeyRing))
                                    .containsOnly("�amonn McManus <eamonn@mcmanus.net>")
                    );
        }
    }

    @Test
    public void validateSubKeyWithExternalSignature() throws IOException, PGPException {

        try (InputStream inputStream = getClass().getResourceAsStream("/3D8B00E198E21827.asc")) {
            Optional<PGPPublicKeyRing> aPublicKeyRing = PublicKeyUtils.loadPublicKeyRing(inputStream, 0x3D8B00E198E21827L);

            assertThat(aPublicKeyRing)
                    .hasValueSatisfying(publicKeyRing ->
                            assertThat(PublicKeyUtils.getUserIDs(publicKeyRing.getPublicKey(0x3D8B00E198E21827L), publicKeyRing))
                                    .containsOnly("Rick Hillegas <rhillegas@apache.org>")
                    );
        }
    }

    @Test
    public void validateSubKeyWithRevokedSignature() throws IOException, PGPException {

        try (InputStream inputStream = getClass().getResourceAsStream("/411063A3A0FFD119.asc")) {
            Optional<PGPPublicKeyRing> aPublicKeyRing = PublicKeyUtils.loadPublicKeyRing(inputStream, 0x411063A3A0FFD119L);

            assertThat(aPublicKeyRing)
                    .hasValueSatisfying(publicKeyRing ->
                            assertThat(PublicKeyUtils.getUserIDs(publicKeyRing.getPublicKey(0x411063A3A0FFD119L), publicKeyRing))
                                    .hasSize(17)
                                    .contains("Stian Soiland <stain@stud.ntnu.no>")
                    );
        }
    }
}
