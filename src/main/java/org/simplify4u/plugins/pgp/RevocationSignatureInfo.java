/*
 * Copyright 2025 Slawomir Jaranowski
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
package org.simplify4u.plugins.pgp;

import java.util.Date;

import lombok.Builder;
import lombok.Value;

/**
 * Revocation signature data.
 */
@Value
@Builder
public class RevocationSignatureInfo {

    Date date;

    byte reason;

    String description;

    public String getReasonAsString() {
        // https://www.rfc-editor.org/rfc/rfc9580.html#name-reason-for-revocation
        switch (reason) {
            case 0x00:
                return "No reason specified";
            case 0x01:
                return "Key is superseded";
            case 0x02:
                return "Key material has been compromised";
            case 0x03:
                return "Key is retired and no longer used";
            default:
                return String.format("Unknown reason: %X", reason);
        }
    }
}
