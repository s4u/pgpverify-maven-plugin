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

import java.util.Collections;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.simplify4u.plugins.pgp.KeyFingerprint;
import org.simplify4u.plugins.pgp.KeyInfo;
import org.junit.jupiter.api.Test;

/**
 * @author Slawomir Jaranowski.
 */
class KeyItemsTest {

    public static Object[][] keys() {
        return new Object[][]{
                {"*", "0x123456789abcdef0", true},
                {"", "0x123456789abcdef0", false},
                {"any", "0x123456789abcdef0", true},
                {"Any", "0x123456789abcdef0", true},
                {"0x123456789abcdef0", "0x123456789abcdef0", true},
                {"noSig, 0x123456789abcdef0", "0x123456789abcdef0", true},
                {"noKey, 0x123456789abcdef0", "0x123456789abcdef0", true},
                {"badSig, 0x123456789abcdef0", "0x123456789abcdef0", true},
                {"0x123456789abcdef0,0x0fedcba987654321", "0x123456789abcdef0", true},
                {"0x123456789abcdef0, 0x0fedcba987654321", "0x123456789abcdef0", true},
                {"0x123456789abcdef0", "0x231456789abcdef0", false},
                {"0x12 34 56 78 9a bc de f0", "0x123456789abcdef0", true},
                {"0x123456789abcdef0, *", "0x231456789abcdef0", true},
                {"0x123456789abcdef0, 0x0fedcba987654321", "0x321456789abcdef0", false},
                {"0x0000000000000001", "0x0000000000000001", true}
        };
    }

    @ParameterizedTest
    @MethodSource("keys")
    void testIsKeyMatch(String strKeys, String key, boolean match) {

        KeyItems keyItems = new KeyItems().addKeys(strKeys, null);
        assertThat(keyItems.isKeyMatch(aKeyInfo(key))).as("isKeyMatch").isEqualTo(match);
    }

    private KeyInfo aKeyInfo(String fingerprint) {
        return KeyInfo.builder().fingerprint(new KeyFingerprint(fingerprint)).build();
    }

    @Test
    void nullKeyShouldThrowsException() {
        // given
        KeysMapContext keysMapContext = new KeysMapContext("test.map");
        KeyItems keyItems = new KeyItems();

        // then
        assertThatThrownBy(() -> keyItems.addKeys((String) null, keysMapContext))
                .isExactlyInstanceOf(IllegalArgumentException.class)
                .hasMessage("null key not allowed in keysMap: test.map lineNumber: 0");
    }

    @Test
    void invalidKeyShouldThrowsException() {
        // given
        KeyItems keyItems = new KeyItems();
        KeysMapContext keysMapContext = new KeysMapContext("test.map");
        keysMapContext.incLineNumber();
        // then
        assertThatThrownBy(() -> keyItems.addKeys("xxxx", keysMapContext))
                .isExactlyInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid keyID xxxx must start with 0x or !0x or be any of *,any,badSig,noKey,noSig "
                        + "in: keysMap: test.map lineNumber: 1");
    }


    @Test
    void testIsNoSignature() {

        KeyItems keyItems = new KeyItems().addKeys("", null);
        assertThat(keyItems.isNoSignature()).isTrue();
    }

    @Test
    void testIsNoSignatureIncorrect() {

        KeyItems keyItems = new KeyItems().addKeys("0x123456789abcdef0", null);
        assertThat(keyItems.isNoSignature()).isFalse();
    }

    @Test
    void testSubKeyMach() {

        KeyInfo keyInfo = KeyInfo.builder()
                .fingerprint(new KeyFingerprint("0x1234567890123456789012345678901234567890"))
                .master(new KeyFingerprint("0x0987654321098765432109876543210987654321"))
                .build();

        // keyItems with master key fingerprint
        KeyItems keyItems = new KeyItems().addKeys(keyInfo.getMaster().toString(), null);

        assertThat(keyItems.isKeyMatch(keyInfo)).isTrue();
    }

    @Test
    void oddHexStringShouldThrowException() {
        // given
        KeyItems keyItems = new KeyItems();

        // then
        assertThatThrownBy(() -> keyItems.addKeys("0x123456789abcdef", null))
                .isExactlyInstanceOf(IllegalArgumentException.class)
                .hasMessage("Malformed keyID hex string 0x123456789abcdef");
    }

    @Test
    void invalidHexStringShouldThrowException() {
        // given
        KeyItems keyItems = new KeyItems();

        // then
        assertThatThrownBy(() -> keyItems.addKeys("0xINVALID", null))
                .isExactlyInstanceOf(IllegalArgumentException.class)
                .hasMessage("Malformed keyID hex string 0xINVALID");
    }

    @Test
    void onlyIncludedValuesShouldBePreserved() {
        KeysMapContext keysMapContext = new KeysMapContext("test.map");
        KeyItems keyItems = new KeyItems().addKeys("noSig, badSig, noKey, 0x123456789abcdef0", keysMapContext);

        assertThat(keyItems.isNoSignature()).isTrue();
        assertThat(keyItems.isBrokenSignature()).isTrue();
        assertThat(keyItems.isKeyMissing()).isTrue();
        assertThat(keyItems.isKeyMatch(aKeyInfo("0x123456789abcdef0"))).isTrue();

        keyItems.includes(asList(KeyItemSpecialValue.NO_SIG.getKeyItem(), KeyItemSpecialValue.NO_KEY.getKeyItem()));

        assertThat(keyItems.isNoSignature()).isTrue();
        assertThat(keyItems.isBrokenSignature()).isFalse();
        assertThat(keyItems.isKeyMissing()).isTrue();
        assertThat(keyItems.isKeyMatch(aKeyInfo("0x123456789abcdef0"))).isFalse();
    }

    @Test
    void includedAnyValuesShouldDoNothing() {
        KeysMapContext keysMapContext = new KeysMapContext("test.map");
        KeyItems keyItems = new KeyItems().addKeys("noSig, badSig, noKey, 0x123456789abcdef0", keysMapContext);

        assertThat(keyItems.isNoSignature()).isTrue();
        assertThat(keyItems.isBrokenSignature()).isTrue();
        assertThat(keyItems.isKeyMissing()).isTrue();
        assertThat(keyItems.isKeyMatch(aKeyInfo("0x123456789abcdef0"))).isTrue();

        keyItems.includes(singletonList(KeyItemSpecialValue.ANY.getKeyItem()));

        assertThat(keyItems.isNoSignature()).isTrue();
        assertThat(keyItems.isBrokenSignature()).isTrue();
        assertThat(keyItems.isKeyMissing()).isTrue();
        assertThat(keyItems.isKeyMatch(aKeyInfo("0x123456789abcdef0"))).isTrue();
    }

    @Test
    void emptyIncludedValuesRemoveAllItems() {
        KeysMapContext keysMapContext = new KeysMapContext("test.map");
        KeyItems keyItems = new KeyItems().addKeys("noSig, badSig, noKey, 0x123456789abcdef0", keysMapContext);

        assertThat(keyItems.isEmpty()).isFalse();

        keyItems.includes(Collections.emptyList());

        assertThat(keyItems.isEmpty()).isTrue();
    }

    @Test
    void excludedValuesShouldBeRemoved() {
        KeysMapContext keysMapContext = new KeysMapContext("test.map");
        KeyItems keyItems = new KeyItems().addKeys("noSig, badSig, noKey, 0x123456789abcdef0", keysMapContext);

        assertThat(keyItems.isNoSignature()).isTrue();
        assertThat(keyItems.isBrokenSignature()).isTrue();
        assertThat(keyItems.isKeyMissing()).isTrue();
        assertThat(keyItems.isKeyMatch(aKeyInfo("0x123456789abcdef0"))).isTrue();

        keyItems.excludes(asList(KeyItemSpecialValue.NO_SIG.getKeyItem(), KeyItemSpecialValue.NO_KEY.getKeyItem()));

        assertThat(keyItems.isNoSignature()).isFalse();
        assertThat(keyItems.isBrokenSignature()).isTrue();
        assertThat(keyItems.isKeyMissing()).isFalse();
        assertThat(keyItems.isKeyMatch(aKeyInfo("0x123456789abcdef0"))).isTrue();
    }

    @Test
    void emptyExcludedValuesDoNothing() {
        KeysMapContext keysMapContext = new KeysMapContext("test.map");
        KeyItems keyItems = new KeyItems().addKeys("noSig, badSig, noKey, 0x123456789abcdef0", keysMapContext);

        assertThat(keyItems.isNoSignature()).isTrue();
        assertThat(keyItems.isBrokenSignature()).isTrue();
        assertThat(keyItems.isKeyMissing()).isTrue();
        assertThat(keyItems.isKeyMatch(aKeyInfo("0x123456789abcdef0"))).isTrue();

        keyItems.excludes(Collections.emptyList());

        assertThat(keyItems.isNoSignature()).isTrue();
        assertThat(keyItems.isBrokenSignature()).isTrue();
        assertThat(keyItems.isKeyMissing()).isTrue();
        assertThat(keyItems.isKeyMatch(aKeyInfo("0x123456789abcdef0"))).isTrue();
    }

}
