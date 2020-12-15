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

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.function.Supplier;
import javax.inject.Inject;

import io.vavr.control.Try;
import lombok.AccessLevel;
import lombok.Setter;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.Parameter;
import org.simplify4u.plugins.keyserver.PGPKeysCache;
import org.simplify4u.plugins.utils.PGPSignatureUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract Mojo with common features for other goals
 */
public abstract class AbstractPGPMojo extends AbstractMojo {

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractPGPMojo.class);

    @Inject
    protected ArtifactResolver artifactResolver;

    @Inject
    protected PGPKeysCache pgpKeysCache;

    @Inject
    protected PGPSignatureUtils pgpSignatureUtils;

    @Inject
    protected MavenSession session;

    /**
     * The directory for storing cached PGP public keys.
     *
     * @since 1.0.0
     */
    @Parameter(property = "pgpverify.keycache", required = true,
            defaultValue = "${settings.localRepository}/pgpkeys-cache")
    private File pgpKeysCachePath;

    /**
     * PGP public key servers address.
     *
     * <p>
     * From version <b>1.7.0</b> you can provide many kay servers separated by comma, semicolon or whitespace.
     *
     * @since 1.0.0
     */
    @Parameter(property = "pgpverify.keyserver", required = true,
            defaultValue = "hkps://hkps.pool.sks-keyservers.net,hkps://keyserver.ubuntu.com")
    private String pgpKeyServer;

    /**
     * Choose which proxy to use (id from settings.xml in maven config). Uses no proxy if the proxy was not found. If it
     * is not set, it will take the first active proxy if any or no proxy, if no active proxy was found)
     *
     * @since 1.8.0
     */
    @Parameter(property = "pgpverify.proxyName")
    private String proxyName;

    /**
     * Skip verification altogether.
     *
     * @since 1.3.0
     */
    @Parameter(property = "pgpverify.skip", defaultValue = "false")
    @Setter(AccessLevel.PACKAGE)
    private boolean skip;

    /**
     * If many key server is provided, use all of them.
     * <p>
     * If set to false only first key server will be used, another as fallback.
     *
     * @since 1.7.0
     */
    @Parameter(property = "pgpverify.keyserversLoadBalance", defaultValue = "true")
    private boolean pgpKeyServerLoadBalance;

    /**
     * Only log errors.
     *
     * @since 1.4.0
     */
    @Parameter(property = "pgpverify.quiet", defaultValue = "false")
    private boolean quiet;

    @Override
    public final Log getLog() {
        throw new UnsupportedOperationException("SLF4J should be used directly");
    }

    /**
     * @return Mojo name for current class.
     */
    protected abstract String getMojoName();

    protected abstract void executeConfiguredMojo() throws MojoExecutionException, MojoFailureException;

    private void initPgpKeysCache() throws IOException {
        pgpKeysCache.init(pgpKeysCachePath, pgpKeyServer, pgpKeyServerLoadBalance, proxyName);
    }

    @Override
    public final void execute() throws MojoExecutionException, MojoFailureException {

        if (skip) {
            LOGGER.info("Skipping pgpverify:{}", getMojoName());
            return;
        }

        Try.run(this::initPgpKeysCache)
                .getOrElseThrow(e -> new MojoFailureException(e.getMessage(), e));

        executeConfiguredMojo();
    }

    protected void logWithQuiet(String message) {
        if (quiet) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(message);
            }
        } else {
            LOGGER.info(message);
        }
    }

    protected void logWithQuiet(String message, Supplier<?>... args) {
        if (quiet) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(message, Arrays.stream(args).map(Supplier::get).toArray());
            }
        } else {
            LOGGER.info(message, Arrays.stream(args).map(Supplier::get).toArray());
        }
    }

}
