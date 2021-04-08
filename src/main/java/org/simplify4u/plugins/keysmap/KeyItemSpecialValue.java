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

import java.util.Arrays;
import java.util.Comparator;
import java.util.Optional;
import java.util.stream.Collectors;

import lombok.Getter;

@Getter
enum KeyItemSpecialValue {

    ANY0("*", new KeyItemAnyKey()),
    ANY(KeyItemAnyKey.DESC, new KeyItemAnyKey()),
    BAD_SIG(KeyItemBrokenSig.DESC, new KeyItemBrokenSig()),
    NO_KEY(KeyItemNoKey.DESC, new KeyItemNoKey()),
    NO_SIG(KeyItemNoSig.DESC, new KeyItemNoSig());

    private final String desc;
    private final KeyItem keyItem;

    KeyItemSpecialValue(String desc, KeyItem keyItem) {
        this.desc = desc;
        this.keyItem = keyItem;
    }

    public static String getAllowedValue() {
        return Arrays.stream(values())
                .sorted(Comparator.comparing(o -> o.desc))
                .map(KeyItemSpecialValue::getDesc)
                .collect(Collectors.joining(","));
    }

    /**
     * Find special keyItem by description.
     *
     * @param desc a given description
     *
     * @return keyItem for description
     */
    public static Optional<KeyItem> keyItemFromString(String desc) {
        return Arrays.stream(values())
                .filter(value -> value.desc.equalsIgnoreCase(desc))
                .map(KeyItemSpecialValue::getKeyItem)
                .findAny();
    }
}
