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

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.function.Supplier;
import javax.inject.Inject;

import lombok.AccessLevel;
import lombok.Setter;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.Parameter;
import org.simplify4u.plugins.keyserver.KeyCacheSettings;
import org.simplify4u.plugins.keyserver.KeyServerClientSettings;
import org.simplify4u.plugins.keyserver.PGPKeysCache;
import org.simplify4u.plugins.pgp.SignatureUtils;
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
    protected SignatureUtils signatureUtils;

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
     * When key does not exist on key servers such information will be stored in cache.
     * <p>
     * Next checking for key existence will be done after specific hours remain.
     *
     * @since 1.15.0
     */
    @Parameter(defaultValue = "24")
    private int keyNotFoundRefreshHour;

    /**
     * PGP public key servers address.
     *
     * <p>
     * From version <b>1.7.0</b> you can provide many key servers separated by comma, semicolon or whitespace.
     *
     * <p>
     * From version <b>1.15.0</b> hkp/http protocols are deprecated - please use hkps/https for key servers.
     *
     * @since 1.0.0
     */
    @Parameter(property = "pgpverify.keyserver", required = true,
            defaultValue = "hkps://keyserver.ubuntu.com, hkps://keys.openpgp.org, hkps://pgp.mit.edu")
    private String pgpKeyServer;

    /**
     * Choose which proxy to use (id from settings.xml in maven config). Uses no proxy if the proxy was not found. If it
     * is not set, it will take the first active proxy if any or no proxy, if no active proxy was found.
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
     * If many key servers are provided, use all of them.
     * <p>
     * If set to false only first key server will be used, another as fallback.
     *
     * @since 1.7.0
     */
    @Parameter(property = "pgpverify.keyserversLoadBalance", defaultValue = "false")
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

    protected abstract void executeConfiguredMojo();

    /**
     * check and warn if any of the deprecated options are used.
     */
    protected void checkDeprecated() {
    }

    protected void setupMojo() throws MojoFailureException {

        KeyServerClientSettings clientSettings = KeyServerClientSettings.builder()
                .mavenSession(session)
                .proxyName(proxyName)
                .build();

        KeyCacheSettings cacheSettings = KeyCacheSettings.builder()
                .cachePath(pgpKeysCachePath)
                .keyServers(pgpKeyServer)
                .loadBalance(pgpKeyServerLoadBalance)
                .notFoundRefreshHours(keyNotFoundRefreshHour)
                .offLine(session.isOffline())
                .build();

        try {
            pgpKeysCache.init(cacheSettings, clientSettings);
        } catch (IOException e) {
            throw new MojoFailureException(e.getMessage(), e);
        }
    }

    @Override
    public final void execute() throws MojoExecutionException, MojoFailureException {

        if (skip) {
            LOGGER.info("Skipping pgpverify:{}", getMojoName());
            return;
        }

        setupMojo();
        checkDeprecated();
        executeConfiguredMojo();
    }

    protected void logInfoWithQuiet(String message) {
        if (quiet) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(message);
            }
        } else {
            LOGGER.info(message);
        }
    }

    protected void logInfoWithQuiet(String message, Supplier<?>... args) {
        if (quiet) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(message, Arrays.stream(args).map(Supplier::get).toArray());
            }
        } else {
            LOGGER.info(message, Arrays.stream(args).map(Supplier::get).toArray());
        }
    }

    protected void logWarnWithQuiet(String message, Supplier<?>... args) {
        if (quiet) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(message, Arrays.stream(args).map(Supplier::get).toArray());
            }
        } else {
            LOGGER.warn(message, Arrays.stream(args).map(Supplier::get).toArray());
        }
    }

}
