/*
 * Copyright 2020 Slawomir Jaranowski
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
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

/**
 * Store info about key numbers.
 *
 * @author Slawomir Jaranowski.
 */
class KeyInfo {

    private static final Map<String, KeyInfoItem> SPECIAL_KEYS = Stream.of(
            new SimpleEntry<>("*", new KeyInfoItemAnyKey()),
            new SimpleEntry<>("any", new KeyInfoItemAnyKey()),
            new SimpleEntry<>("badSig", new KeyInfoItemBrokenSig()),
            new SimpleEntry<>("noKey", new KeyInfoItemNoKey()),
            new SimpleEntry<>("noSig", new KeyInfoItemNoSig())
    ).collect(Collectors.toMap(Entry::getKey, Entry::getValue));

    private final List<KeyInfoItem> keys = new ArrayList<>();


    public KeyInfo(String strKeys) {

        if (strKeys == null) {
            throw new IllegalArgumentException("null key not allowed");
        }

        // compatibility behavior
        if (strKeys.trim().isEmpty()) {
            keys.add(new KeyInfoItemNoSig());
            return;
        }

        Arrays.stream(strKeys.split(","))
                .map(String::trim)
                .forEach(key -> {

                    if (key.startsWith("0x")) {
                        keys.add(new KeyInfoItemKey(key));
                    } else {

                        Optional<KeyInfoItem> keyInfoItem = SPECIAL_KEYS.entrySet().stream()
                                .filter(entry -> entry.getKey().equalsIgnoreCase(key))
                                .map(Entry::getValue)
                                .findFirst();
                        keys.add(keyInfoItem.orElseThrow(()
                                -> new IllegalArgumentException("Invalid keyID " + key + " must start with 0x "
                                + "or be any of " + SPECIAL_KEYS.keySet())));
                    }
                });
    }

    public boolean isKeyMatch(PGPPublicKey pgpPublicKey, PGPPublicKeyRing pgpPublicKeyRing) {
        return keys.stream().anyMatch(keyInfoItem -> keyInfoItem.isKeyMatch(pgpPublicKey, pgpPublicKeyRing));
    }

    public boolean isNoSignature() {
        return keys.stream().anyMatch(KeyInfoItem::isNoSignature);
    }

    public boolean isKeyMissing() {
        return keys.stream().anyMatch(KeyInfoItem::isKeyMissing);
    }

    public boolean isBrokenSignature() {
        return keys.stream().anyMatch(KeyInfoItem::isBrokenSignature);
    }
}
