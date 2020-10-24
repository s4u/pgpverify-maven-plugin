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
package org.simplify4u.plugins;


import java.util.Arrays;

/**
 * Common runtime exception for Maven mojo.
 *
 * @author Slawomir Jaaranowski
 */
public class PGPMojoException extends RuntimeException {

    private static class Formatter {

        String message;
        Throwable cause;

        public Formatter(String messageToFormat, Object[] args) {
            Object[] argsToFormat;
            Object last = args.length > 0 ? args[args.length - 1] : null;
            if (last instanceof Throwable) {
                argsToFormat = Arrays.copyOf(args, args.length - 1);
                cause = (Throwable) last;
            } else {
                argsToFormat = args;
            }
            message = String.format(messageToFormat, argsToFormat);
        }
    }

    private static final long serialVersionUID = -2691735554566086599L;

    public PGPMojoException() {
        super();
    }

    public PGPMojoException(Throwable cause) {
        super(cause);
    }

    public PGPMojoException(String message) {
        super(message);
    }

    /**
     * Message can contains {@link String#format(String, Object...)} placeholders.
     * <p>
     * If last argument is Throwable, then will be used as a cause of exception.
     *
     * @param message message of exception
     * @param args    additional args for message formatting
     */
    public PGPMojoException(String message, Object... args) {
        this(new Formatter(message, args));
    }

    private PGPMojoException(Formatter format) {
        super(format.message, format.cause);
    }
}
