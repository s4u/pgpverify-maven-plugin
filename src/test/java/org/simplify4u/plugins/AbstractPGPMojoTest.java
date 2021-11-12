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
package org.simplify4u.plugins;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.testng.MockitoTestNGListener;
import org.simplify4u.plugins.keyserver.PGPKeysCache;
import org.slf4j.Logger;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

@Listeners(MockitoTestNGListener.class)
public class AbstractPGPMojoTest {

    static class TestMojo extends AbstractPGPMojo {

        @Override
        protected String getMojoName() {
            return "testMojo";
        }

        @Override
        protected void executeConfiguredMojo() {
        }
    }

    @Mock
    private Logger logger;

    @Mock
    private PGPKeysCache pgpKeysCache;

    @Mock
    private MavenSession mavenSession;

    @Spy
    @InjectMocks
    private TestMojo mojo;

    @Test
    void getLogThrowException() {

        assertThatThrownBy(mojo::getLog)
                .isExactlyInstanceOf(UnsupportedOperationException.class)
                .hasMessage("SLF4J should be used directly");
    }

    @Test
    void shouldSkipExecution() throws MojoFailureException, MojoExecutionException {
        // give
        mojo.setSkip(true);

        // when
        mojo.execute();

        // then
        verify(mojo, never()).executeConfiguredMojo();
        verify(logger).info("Skipping pgpverify:{}", "testMojo");
        verifyNoInteractions(pgpKeysCache);
    }

    @Test
    void shouldExecute() throws MojoFailureException, MojoExecutionException, IOException {

        // when
        mojo.execute();

        // then
        verify(mojo).executeConfiguredMojo();
        verify(pgpKeysCache).init(any(), any());
        verifyNoInteractions(logger);
    }
}
