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

import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

/**
 * Store list of fingerprints and special key value for given artifact pattern in keysMap.
 *
 * @author Slawomir Jaranowski.
 */
@Slf4j
class KeyItems {

    private static final Map<String, KeyItem> SPECIAL_KEYS = Stream.of(
            new SimpleEntry<>("*", new KeyItemAnyKey()),
            new SimpleEntry<>(KeyItemAnyKey.DESC, new KeyItemAnyKey()),
            new SimpleEntry<>(KeyItemBrokenSig.DESC, new KeyItemBrokenSig()),
            new SimpleEntry<>(KeyItemNoKey.DESC, new KeyItemNoKey()),
            new SimpleEntry<>(KeyItemNoSig.DESC, new KeyItemNoSig())
    ).collect(Collectors.toMap(Entry::getKey, Entry::getValue));

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
            LOGGER.warn("Empty value for key is deprecated - please provide some  value - now assume as noSig in: {}",
                    keysMapContext);
            addKey(SPECIAL_KEYS.get(KeyItemNoSig.DESC), keysMapContext);
            return this;
        }

        Arrays.stream(strKeys.split(","))
                .map(String::trim)
                .forEach(key -> {

                    if (key.startsWith("0x")) {
                        addKey(new KeyItemFingerprint(key), keysMapContext);
                    } else {

                        KeyItem keyInfoItem = SPECIAL_KEYS.entrySet().stream()
                                .filter(entry -> entry.getKey().equalsIgnoreCase(key))
                                .map(Entry::getValue)
                                .findFirst()
                                .orElseThrow(()
                                        -> new IllegalArgumentException("Invalid keyID " + key + " must start with 0x "
                                        + "or be any of " + SPECIAL_KEYS.keySet()));
                        addKey(keyInfoItem, keysMapContext);
                    }
                });

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

    public boolean isKeyMatch(PGPPublicKey pgpPublicKey, PGPPublicKeyRing pgpPublicKeyRing) {
        return keys.stream().anyMatch(keyInfoItem -> keyInfoItem.isKeyMatch(pgpPublicKey, pgpPublicKeyRing));
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
}
