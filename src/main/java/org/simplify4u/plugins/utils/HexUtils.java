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
package org.simplify4u.plugins.utils;

import lombok.experimental.UtilityClass;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;

/**
 * Utility for converting finger to / from string
 */
@UtilityClass
public class HexUtils {

    /**
     * Convert byte array of fingerprint to string of hex
     * @param bytes fingerprint
     * @return fingerprint as string
     */
    public static String fingerprintToString(byte[] bytes) {
        StringBuilder ret = new StringBuilder();
        ret.append("0x");
        for (byte b : bytes) {
            ret.append(String.format("%02X", b));
        }
        return ret.toString();
    }

    /**
     * Convert fingerprint in string format to byte array.
     * @param key fingerprint as string
     * @return fingerprint as byte array
     */
    public static byte[] stringToFingerprint(String key) {
        byte[] bytes;

        try {
            bytes = Hex.decode(key.substring(2));
        } catch (DecoderException e) {
            throw new IllegalArgumentException("Malformed keyID hex string " + key, e);
        }

        if (bytes.length < 8 || bytes.length > 20) {
            throw new IllegalArgumentException(
                    String.format("Key length for = %s is %d bits, should be between 64 and 160 bits",
                            key, bytes.length * 8));
        }

        return bytes;
    }
}
