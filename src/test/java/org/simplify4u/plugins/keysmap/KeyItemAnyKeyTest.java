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

class KeyItemAnyKeyTest {

    @Test
    void twoInstanceShouldBeEqual() {
        KeyItemAnyKey keyItemAnyKey1 = new KeyItemAnyKey();
        KeyItemAnyKey keyItemAnyKey2 = new KeyItemAnyKey();

        Assertions.assertThat(keyItemAnyKey1)
                .isNotSameAs(keyItemAnyKey2)
                .isEqualTo(keyItemAnyKey2)
                .hasSameHashCodeAs(keyItemAnyKey2);
    }
}
