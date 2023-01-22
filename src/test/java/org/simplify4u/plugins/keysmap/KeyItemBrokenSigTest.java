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

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class KeyItemBrokenSigTest {

    @Test
    void twoInstanceShouldBeEqual() {
        KeyItemBrokenSig keyItemBrokenSig1 = new KeyItemBrokenSig();
        KeyItemBrokenSig keyItemBrokenSig2 = new KeyItemBrokenSig();

        Assertions.assertThat(keyItemBrokenSig1)
                .isNotSameAs(keyItemBrokenSig2)
                .isEqualTo(keyItemBrokenSig2)
                .hasSameHashCodeAs(keyItemBrokenSig2);
    }
}
