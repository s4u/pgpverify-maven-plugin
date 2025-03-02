/*
 * Copyright 2020-2025 Slawomir Jaranowski
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

import lombok.Builder;
import lombok.Value;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;

/**
 * Package contains a public key ring and / or revocation signature.
 */
@Value
@Builder
public class PublicKeyRingPack {

    public static final PublicKeyRingPack EMPTY = PublicKeyRingPack.builder().build();

    PGPPublicKeyRing publicKeyRing;
    PGPSignature revocationSignature;

    public boolean isEmpty() {
        return publicKeyRing == null && revocationSignature == null;
    }

    /**
     * Check availability of public key.
     *
     * @return true if public key is available
     */
    public boolean hasPublicKeys() {
        return publicKeyRing != null;
    }

    /**
     * Check availability of revocation signature.
     *
     * @return true if revocation signature is available.
     */
    public boolean hasRevocationSignature() {
        return revocationSignature != null;
    }
}
