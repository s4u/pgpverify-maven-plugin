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

import static org.assertj.core.api.Assertions.assertThat;

import org.testng.annotations.Test;

public class PGPMojoExceptionTest {

    @Test
    void emptyMessage() {

        PGPMojoException exception = new PGPMojoException();

        assertThat(exception)
                .hasMessage(null)
                .hasRootCause(null);
    }

    @Test
    void simpleMessage() {

        PGPMojoException exception = new PGPMojoException("exception message");

        assertThat(exception)
                .hasMessage("exception message")
                .hasRootCause(null);
    }

    @Test
    void simpleMessageWithException() {

        Exception cause = new Exception();
        PGPMojoException exception = new PGPMojoException("exception message", cause);

        assertThat(exception)
                .hasMessage("exception message")
                .hasRootCause(cause);
    }

    @Test
    void paramsInMessage() {

        PGPMojoException exception = new PGPMojoException("exception message: %d and %s", 1, "second");

        assertThat(exception)
                .hasMessage("exception message: 1 and second")
                .hasRootCause(null);
    }

    @Test
    void paramsInMessageWithException() {

        Exception cause = new Exception();
        PGPMojoException exception = new PGPMojoException("exception message: %d and %s", 1, "second", cause);

        assertThat(exception)
                .hasMessage("exception message: 1 and second")
                .hasRootCause(cause);
    }

    @Test
    void onlyException() {
        Exception cause = new Exception();
        PGPMojoException exception = new PGPMojoException(cause);

        assertThat(exception)
                .hasMessage("java.lang.Exception")
                .hasRootCause(cause);
    }

}
