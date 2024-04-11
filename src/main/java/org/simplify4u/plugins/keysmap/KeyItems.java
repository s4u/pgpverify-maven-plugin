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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.simplify4u.plugins.pgp.KeyInfo;

/**
 * Store list of fingerprints and special key value for given artifact pattern in keysMap.
 *
 * @author Slawomir Jaranowski.
 */
@Slf4j
@ToString
class KeyItems {

    private final List<KeyItem> keys = new ArrayList<>();

    /**
     * Add new keys to current list.
     *
     * @param strKeys        a keys definition from keysMap
     * @param keysMapContext a context of current processing
     *
     * @return a current object instance
     */
    public KeyItems addKeys(String strKeys, KeysMapContext keysMapContext) {

        if (strKeys == null) {
            throw new IllegalArgumentException("null key not allowed in " + keysMapContext);
        }

        // compatibility behavior
        if (strKeys.trim().isEmpty()) {
            LOGGER.warn("Empty value for key is deprecated - please provide some value - now assume as noSig in: {}",
                    keysMapContext);
            addKey(KeyItemSpecialValue.NO_SIG.getKeyItem(), keysMapContext);
            return this;
        }

        Arrays.stream(strKeys.split(","))
                .map(String::trim)
                .forEach(key -> {

                    if (key.startsWith("0x")) {
                        addKey(new KeyItemFingerprint(key), keysMapContext);
                    } else {
                        KeyItem keyInfoItem = KeyItemSpecialValue.keyItemFromString(key)
                                .orElseThrow(()
                                        -> new IllegalArgumentException("Invalid keyID " + key + " must start with 0x "
                                        + "or be any of " + KeyItemSpecialValue.getAllowedValue()));
                        addKey(keyInfoItem, keysMapContext);
                    }
                });

        return this;
    }


    /**
     * Add keys from another KeyItems.
     *
     * @param keyItems       a keyItem with key to add
     * @param keysMapContext a context of current processing
     *
     * @return a current object instance
     */
    public KeyItems addKeys(KeyItems keyItems, KeysMapContext keysMapContext) {
        keyItems.keys.forEach(key -> addKey(key, keysMapContext));
        return this;
    }

    /**
     * Add key to list only if not exist.
     *
     * @param keyItem        a key to add
     * @param keysMapContext a context of current processing
     */
    private void addKey(KeyItem keyItem, KeysMapContext keysMapContext) {
        if (!keys.contains(keyItem)) {
            keys.add(keyItem);
        } else {
            LOGGER.warn("Duplicate key item: {} in: {}", keyItem, keysMapContext);
        }
    }

    /**
     * Check if key match
     * @param keyInfo a key to test
     * @return a result
     */
    public boolean isKeyMatch(KeyInfo keyInfo) {
        return keys.stream().anyMatch(keyInfoItem -> keyInfoItem.isKeyMatch(keyInfo));
    }

    public boolean isNoSignature() {
        return keys.stream().anyMatch(KeyItem::isNoSignature);
    }

    public boolean isKeyMissing() {
        return keys.stream().anyMatch(KeyItem::isKeyMissing);
    }

    public boolean isBrokenSignature() {
        return keys.stream().anyMatch(KeyItem::isBrokenSignature);
    }

    /**
     * Only this values are available.
     *
     * @param values a values that can be on list
     */
    public void includes(List<KeyItem> values) {
        if (values.contains(KeyItemSpecialValue.ANY.getKeyItem())) {
            return;
        }
        keys.removeIf(k -> !values.contains(k));
    }

    /**
     * This value are not allowed.
     *
     * @param values a values to exclude.
     */
    public void excludes(List<KeyItem> values) {
        if (values.isEmpty()) {
            return;
        }
        keys.removeIf(values::contains);
    }

    public boolean isEmpty() {
        return keys.isEmpty();
    }
}
