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

import static org.assertj.core.api.Assertions.assertThat;

import org.testng.annotations.Test;

public class KeyItemFingerprintTest {

    private static final String FINGERPRINT_1 = "0x9ABC DEF0 1234 5678 9ABC DEF0 1234 5678 9ABC DEF0";
    private static final String FINGERPRINT_2 = "0x9ABC DEF0 1234 5678 9ABC DEF0 1234 5678 9ABC 0000";

    @Test
    public void twoInstanceForTheSameKeyShouldBeEqual() {
        KeyItemFingerprint keyItemFingerprint1 = new KeyItemFingerprint(FINGERPRINT_1);
        KeyItemFingerprint keyItemFingerprint2 = new KeyItemFingerprint(FINGERPRINT_1);

        assertThat(keyItemFingerprint1)
                .isNotSameAs(keyItemFingerprint2)
                .isEqualTo(keyItemFingerprint2)
                .hasSameHashCodeAs(keyItemFingerprint2);
    }

    @Test
    public void twoInstanceForTheDifferentKeyShouldNotBeEqual() {
        KeyItemFingerprint keyItemFingerprint1 = new KeyItemFingerprint(FINGERPRINT_1);
        KeyItemFingerprint keyItemFingerprint2 = new KeyItemFingerprint(FINGERPRINT_2);

        assertThat(keyItemFingerprint1)
                .isNotSameAs(keyItemFingerprint2)
                .isNotEqualTo(keyItemFingerprint2)
                .doesNotHaveSameHashCodeAs(keyItemFingerprint2);
    }
}
