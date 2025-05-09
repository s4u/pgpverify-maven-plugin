/*
 * Copyright 2020-2021 Slawomir Jaranowski
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

import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * Result of signature validation.
 */
@Value
@Builder
public class SignatureCheckResult {

    @NonNull
    ArtifactInfo artifact;

    KeyInfo key;
    /**
     * Last address for key search.
     */
    String keyShowUrl;

    SignatureInfo signature;

    RevocationSignatureInfo revocationSignature;

    @NonNull
    SignatureStatus status;

    @JsonIgnore
    Throwable errorCause;

    public String getErrorMessage() {
        return Optional.ofNullable(errorCause).map(Throwable::getMessage).orElse(null);
    }
}
