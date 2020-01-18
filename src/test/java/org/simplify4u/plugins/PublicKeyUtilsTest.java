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

import static org.testng.Assert.*;
import static org.testng.AssertJUnit.assertFalse;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.testng.annotations.Test;

public class PublicKeyUtilsTest {

    @Test
    public void testSubKeysLoad() throws IOException, PGPException {

        try (InputStream inputStream = getClass().getResourceAsStream("/EFE8086F9E93774E.asc")) {
            PGPPublicKeyRing publicKeyRing = PublicKeyUtils.loadPublicKeyRing(inputStream, 0xEFE8086F9E93774EL);

            assertNotNull(publicKeyRing);

            assertTrue(publicKeyRing.getPublicKey().isMasterKey());
            assertFalse(publicKeyRing.getPublicKey(0xEFE8086F9E93774EL).isMasterKey());
        }
    }

    @Test
    public void testSubKeysUserIds() throws IOException, PGPException {

        try (InputStream inputStream = getClass().getResourceAsStream("/EFE8086F9E93774E.asc")) {
            PGPPublicKeyRing publicKeyRing = PublicKeyUtils.loadPublicKeyRing(inputStream, 0xEFE8086F9E93774EL);

            assertNotNull(publicKeyRing);

            assertEquals(PublicKeyUtils.getUserIDs(publicKeyRing.getPublicKey(0xEFE8086F9E93774EL), publicKeyRing),
                    Collections.singletonList("Marc Philipp (JUnit Development, 2014) <mail@marcphilipp.de>"));
        }
    }
}
