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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.simplify4u.plugins.TestUtils.getPGPgpPublicKey;
import static org.testng.Assert.assertEquals;

/**
 * @author Slawomir Jaranowski.
 */
public class KeyInfoTest {

    @DataProvider(name = "keys")
    public Object[][] keys() {
        return new Object[][]{
                {"*", 0x123456789abcdef0L, true},
                {"any", 0x123456789abcdef0L, true},
                {"Any", 0x123456789abcdef0L, true},
                {"ANY", 0x123456789abcdef0L, true},
                {"0x123456789abcdef0", 0x123456789abcdef0L, true},
                {"0x123456789abcdef0,0x0fedcba987654321", 0x123456789abcdef0L, true},
                {"0x123456789abcdef0, 0x0fedcba987654321", 0x123456789abcdef0L, true},
                {"0x123456789abcdef0", 0x231456789abcdef0L, false},
                {"0x123456789abcdef0, 0x0fedcba987654321", 0x321456789abcdef0L, false}
        };
    }

    @Test(dataProvider = "keys")
    public void testIsKeyMatch(String strKeys, long key, boolean match) throws Exception {

        KeyInfo keyInfo = new KeyInfo(strKeys);
        assertEquals(keyInfo.isKeyMatch(getPGPgpPublicKey(key)), match);
    }
}
