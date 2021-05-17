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

/**
 * Exception for signature problem.
 */
public class SignatureException extends Exception {

    private static final long serialVersionUID = -7765012289742692489L;

    /**
     * Exception with message detail.
     * @param message a massage
     */
    public SignatureException(String message) {
        super(message);
    }

    /**
     * Exception with message detail and cause.
     * @param message a message
     * @param cause a cause
     */
    public SignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
