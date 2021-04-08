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

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Optional;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.simplify4u.plugins.TestUtils.getPGPgpPublicKey;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.simplify4u.plugins.utils.PGPKeyId;
import org.simplify4u.plugins.utils.PublicKeyUtils;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * @author Slawomir Jaranowski.
 */
public class KeyItemsTest {

    @DataProvider(name = "keys")
    public Object[][] keys() {
        return new Object[][]{
                {"*", 0x123456789abcdef0L, true},
                {"", 0x123456789abcdef0L, false},
                {"any", 0x123456789abcdef0L, true},
                {"Any", 0x123456789abcdef0L, true},
                {"0x123456789abcdef0", 0x123456789abcdef0L, true},
                {"noSig, 0x123456789abcdef0", 0x123456789abcdef0L, true},
                {"noKey, 0x123456789abcdef0", 0x123456789abcdef0L, true},
                {"badSig, 0x123456789abcdef0", 0x123456789abcdef0L, true},
                {"0x123456789abcdef0,0x0fedcba987654321", 0x123456789abcdef0L, true},
                {"0x123456789abcdef0, 0x0fedcba987654321", 0x123456789abcdef0L, true},
                {"0x123456789abcdef0", 0x231456789abcdef0L, false},
                {"0x12 34 56 78 9a bc de f0", 0x123456789abcdef0L, true},
                {"0x123456789abcdef0, *", 0x231456789abcdef0L, true},
                {"0x123456789abcdef0, 0x0fedcba987654321", 0x321456789abcdef0L, false},
                {"0x0000000000000001", 0x1L, true}
        };
    }

    @Test(dataProvider = "keys")
    public void testIsKeyMatch(String strKeys, long key, boolean match) throws Exception {

        KeyItems keyItems = new KeyItems().addKeys(strKeys, null);
        assertThat(keyItems.isKeyMatch(getPGPgpPublicKey(key), null)).as("isKeyMatch").isEqualTo(match);
    }

    @Test
    public void nullKeyShouldThrowsException() {
        // given
        KeysMapContext keysMapContext = new KeysMapContext("test.map");
        KeyItems keyItems = new KeyItems();

        // then
        assertThatThrownBy(() -> keyItems.addKeys((String) null, keysMapContext))
                .isExactlyInstanceOf(IllegalArgumentException.class)
                .hasMessage("null key not allowed in keysMap: test.map lineNumber: 0");
    }

    @Test
    public void invalidKeyShouldThrowsException() {
        // given
        KeyItems keyItems = new KeyItems();

        // then
        assertThatThrownBy(() -> keyItems.addKeys("xxxx", null))
                .isExactlyInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid keyID xxxx must start with 0x or be any of *,any,badSig,noKey,noSig");
    }


    @Test
    public void testIsNoSignature() {

        KeyItems keyItems = new KeyItems().addKeys("", null);
        assertThat(keyItems.isNoSignature()).isTrue();
    }

    @Test
    public void testIsNoSignatureIncorrect() {

        KeyItems keyItems = new KeyItems().addKeys("0x123456789abcdef0", null);
        assertThat(keyItems.isNoSignature()).isFalse();
    }

    @Test
    public void testSubKeyMach() throws IOException, PGPException {

        try (InputStream inputStream = getClass().getResourceAsStream("/EFE8086F9E93774E.asc")) {
            Optional<PGPPublicKeyRing> aPublicKeyRing = PublicKeyUtils.loadPublicKeyRing(inputStream, PGPKeyId.from(0xEFE8086F9E93774EL));

            assertThat(aPublicKeyRing)
                    .hasValueSatisfying(publicKeyRing -> {
                        // keyItems with master key fingerprint
                        KeyItems keyItems = new KeyItems().addKeys(PublicKeyUtils.fingerprint(publicKeyRing.getPublicKey()), null);

                        assertThat(keyItems.isKeyMatch(publicKeyRing.getPublicKey(0xEFE8086F9E93774EL), publicKeyRing))
                                .isTrue();
                    });
        }
    }

    @Test
    public void oddHexStringShouldThrowException() {
        // given
        KeyItems keyItems = new KeyItems();

        // then
        assertThatThrownBy(() -> keyItems.addKeys("0x123456789abcdef", null))
                .isExactlyInstanceOf(IllegalArgumentException.class)
                .hasMessage("Malformed keyID hex string 0x123456789abcdef");
    }

    @Test
    public void invalidHexStringShouldThrowException() {
        // given
        KeyItems keyItems = new KeyItems();

        // then
        assertThatThrownBy(() -> keyItems.addKeys("0xINVALID", null))
                .isExactlyInstanceOf(IllegalArgumentException.class)
                .hasMessage("Malformed keyID hex string 0xINVALID");
    }

    @Test
    public void onlyIncludedValuesShouldBePreserved() {
        KeysMapContext keysMapContext = new KeysMapContext("test.map");
        KeyItems keyItems = new KeyItems().addKeys("noSig, badSig, noKey, 0x123456789abcdef0", keysMapContext);

        assertThat(keyItems.isNoSignature()).isTrue();
        assertThat(keyItems.isBrokenSignature()).isTrue();
        assertThat(keyItems.isKeyMissing()).isTrue();
        assertThat(keyItems.isKeyMatch(getPGPgpPublicKey(0x123456789abcdef0L), null)).isTrue();

        keyItems.includes(asList(KeyItemSpecialValue.NO_SIG.getKeyItem(), KeyItemSpecialValue.NO_KEY.getKeyItem()));

        assertThat(keyItems.isNoSignature()).isTrue();
        assertThat(keyItems.isBrokenSignature()).isFalse();
        assertThat(keyItems.isKeyMissing()).isTrue();
        assertThat(keyItems.isKeyMatch(getPGPgpPublicKey(0x123456789abcdef0L), null)).isFalse();
    }

    @Test
    public void includedAnyValuesShouldDoNothing() {
        KeysMapContext keysMapContext = new KeysMapContext("test.map");
        KeyItems keyItems = new KeyItems().addKeys("noSig, badSig, noKey, 0x123456789abcdef0", keysMapContext);

        assertThat(keyItems.isNoSignature()).isTrue();
        assertThat(keyItems.isBrokenSignature()).isTrue();
        assertThat(keyItems.isKeyMissing()).isTrue();
        assertThat(keyItems.isKeyMatch(getPGPgpPublicKey(0x123456789abcdef0L), null)).isTrue();

        keyItems.includes(singletonList(KeyItemSpecialValue.ANY.getKeyItem()));

        assertThat(keyItems.isNoSignature()).isTrue();
        assertThat(keyItems.isBrokenSignature()).isTrue();
        assertThat(keyItems.isKeyMissing()).isTrue();
        assertThat(keyItems.isKeyMatch(getPGPgpPublicKey(0x123456789abcdef0L), null)).isTrue();
    }

    @Test
    public void emptyIncludedValuesRemoveAllItems() {
        KeysMapContext keysMapContext = new KeysMapContext("test.map");
        KeyItems keyItems = new KeyItems().addKeys("noSig, badSig, noKey, 0x123456789abcdef0", keysMapContext);

        assertThat(keyItems.isEmpty()).isFalse();

        keyItems.includes(Collections.emptyList());

        assertThat(keyItems.isEmpty()).isTrue();
    }

    @Test
    public void excludedValuesShouldBeRemoved() {
        KeysMapContext keysMapContext = new KeysMapContext("test.map");
        KeyItems keyItems = new KeyItems().addKeys("noSig, badSig, noKey, 0x123456789abcdef0", keysMapContext);

        assertThat(keyItems.isNoSignature()).isTrue();
        assertThat(keyItems.isBrokenSignature()).isTrue();
        assertThat(keyItems.isKeyMissing()).isTrue();
        assertThat(keyItems.isKeyMatch(getPGPgpPublicKey(0x123456789abcdef0L), null)).isTrue();

        keyItems.excludes(asList(KeyItemSpecialValue.NO_SIG.getKeyItem(), KeyItemSpecialValue.NO_KEY.getKeyItem()));

        assertThat(keyItems.isNoSignature()).isFalse();
        assertThat(keyItems.isBrokenSignature()).isTrue();
        assertThat(keyItems.isKeyMissing()).isFalse();
        assertThat(keyItems.isKeyMatch(getPGPgpPublicKey(0x123456789abcdef0L), null)).isTrue();
    }

    @Test
    public void emptyExcludedValuesDoNothing() {
        KeysMapContext keysMapContext = new KeysMapContext("test.map");
        KeyItems keyItems = new KeyItems().addKeys("noSig, badSig, noKey, 0x123456789abcdef0", keysMapContext);

        assertThat(keyItems.isNoSignature()).isTrue();
        assertThat(keyItems.isBrokenSignature()).isTrue();
        assertThat(keyItems.isKeyMissing()).isTrue();
        assertThat(keyItems.isKeyMatch(getPGPgpPublicKey(0x123456789abcdef0L), null)).isTrue();

        keyItems.excludes(Collections.emptyList());

        assertThat(keyItems.isNoSignature()).isTrue();
        assertThat(keyItems.isBrokenSignature()).isTrue();
        assertThat(keyItems.isKeyMissing()).isTrue();
        assertThat(keyItems.isKeyMatch(getPGPgpPublicKey(0x123456789abcdef0L), null)).isTrue();
    }

}
