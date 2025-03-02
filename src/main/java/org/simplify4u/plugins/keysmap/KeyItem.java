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

import org.simplify4u.plugins.pgp.KeyInfo;

/**
 * Describe single key item in keysMap.
 */
interface KeyItem {

    /**
     * Artifact can has no signature.
     *
     * @return signature status
     */
    default boolean isNoSignature() {
        return false;
    }

    /**
     * Artifact can has broken signature.
     *
     * @return broken signature status
     */
    default boolean isBrokenSignature() {
        return false;
    }

    /**
     * Key for signature can be not found on public key servers.
     *
     * @return key missing status
     */
    default boolean isKeyMissing() {
        return false;
    }

    /**
     * Check if current key mach with given key.
     *
     * @param keyInfo key to test
     *
     * @return key matching status
     */
    default boolean isKeyMatch(KeyInfo keyInfo) {
        return false;
    }

    /**
     * Check if current key mach with given key and allow with missing public kay.
     *
     * @param keyInfo key to test
     *
     * @return key matching status
     */
    default boolean isKeyMatchNoPublicKey(KeyInfo keyInfo) {
        return false;
    }

}
