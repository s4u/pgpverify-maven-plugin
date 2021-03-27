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
import org.testng.annotations.Test;

public class KeyItemNoSigTest {

    @Test
    public void twoInstanceShouldBeEqual() {
        KeyItemNoSig keyItemNoSig1 = new KeyItemNoSig();
        KeyItemNoSig keyItemNoSig2 = new KeyItemNoSig();

        Assertions.assertThat(keyItemNoSig1)
                .isNotSameAs(keyItemNoSig2)
                .isEqualTo(keyItemNoSig2)
                .hasSameHashCodeAs(keyItemNoSig2);
    }

}
