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
package org.simplify4u.plugins;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

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
            publicKeyRing = PublicKeyUtils.loadPublicKeyRing(inputStream, SUB_KEY_ID);
            assertNotNull(publicKeyRing);
        }
    }


    @Test
    public void fingerPrintForMasterWithSubKey() {

        PGPPublicKey key = publicKeyRing.getPublicKey(SUB_KEY_ID);

        assertFalse(key.isMasterKey());
        assertEquals(
                PublicKeyUtils.fingerprintForMaster(key, publicKeyRing),
                "0x58E79B6ABC762159DC0B1591164BD2247B936711");
    }

    @Test
    public void fingerPrintForMasterWithMasterKey() throws IOException, PGPException {

        PGPPublicKey key = publicKeyRing.getPublicKey(MASTER_KEY_ID);

        assertTrue(key.isMasterKey());
        assertEquals(
                PublicKeyUtils.fingerprintForMaster(key, publicKeyRing),
                "0x58E79B6ABC762159DC0B1591164BD2247B936711");
    }

    @Test
    public void userIdsWithSubKey() throws IOException, PGPException {

        PGPPublicKey key = publicKeyRing.getPublicKey(SUB_KEY_ID);

        assertFalse(key.isMasterKey());
        assertEquals(
                PublicKeyUtils.getUserIDs(key, publicKeyRing),
                Collections.singletonList("Marc Philipp (JUnit Development, 2014) <mail@marcphilipp.de>"));
    }

    @Test
    public void userIdsWithMasterKey() throws IOException, PGPException {

        PGPPublicKey key = publicKeyRing.getPublicKey(MASTER_KEY_ID);

        assertTrue(key.isMasterKey());
        assertEquals(
                PublicKeyUtils.getUserIDs(key, publicKeyRing),
                Collections.singletonList("Marc Philipp (JUnit Development, 2014) <mail@marcphilipp.de>"));
    }

    @Test
    public void keyIdDescriptionForMasterKey() {
        PGPPublicKey key = publicKeyRing.getPublicKey(MASTER_KEY_ID);

        assertTrue(key.isMasterKey());
        assertEquals(PublicKeyUtils.keyIdDescription(key, publicKeyRing), "KeyId: 0x58E79B6ABC762159DC0B1591164BD2247B936711");
    }

    @Test
    public void keyIdDescriptionForSubKey() {
        PGPPublicKey key = publicKeyRing.getPublicKey(SUB_KEY_ID);

        assertFalse(key.isMasterKey());
        assertEquals(PublicKeyUtils.keyIdDescription(key, publicKeyRing), "SubKeyId: 0xEFE8086F9E93774E of 0x58E79B6ABC762159DC0B1591164BD2247B936711");
    }

    @Test
    public void invalidUTF8InUserId() throws IOException, PGPException {

        try (InputStream inputStream = getClass().getResourceAsStream("/B0F3710FA64900E7.asc")) {
            PGPPublicKeyRing publicKeyRing = PublicKeyUtils.loadPublicKeyRing(inputStream, 0xB0F3710FA64900E7L);

            assertNotNull(publicKeyRing);

            assertEquals(PublicKeyUtils.getUserIDs(publicKeyRing.getPublicKey(0xB0F3710FA64900E7L), publicKeyRing),
                    Collections.singletonList("�amonn McManus <eamonn@mcmanus.net>"));
        }
    }

    @Test
    public void invalidDerbyClient() throws IOException, PGPException {

        try (InputStream inputStream = getClass().getResourceAsStream("/3D8B00E198E21827.asc")) {
            PGPPublicKeyRing publicKeyRing = PublicKeyUtils.loadPublicKeyRing(inputStream, 0x3D8B00E198E21827L);

            assertNotNull(publicKeyRing);

            assertEquals(PublicKeyUtils.getUserIDs(publicKeyRing.getPublicKey(0x3D8B00E198E21827L), publicKeyRing),
                    Collections.singletonList("Rick Hillegas <rhillegas@apache.org>"));
        }
    }
}
