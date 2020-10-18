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
import javax.inject.Inject;

import io.vavr.control.Try;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Parameter;
import org.codehaus.plexus.resource.loader.ResourceNotFoundException;
import org.simplify4u.plugins.keyserver.PGPKeysCache;
import org.simplify4u.plugins.keysmap.KeysMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract Mojo with common features for other goals
 */
public abstract class AbstractPGPMojo extends AbstractMojo {

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractPGPMojo.class);

    @Inject
    protected MavenSession session;

    @Inject
    protected PGPKeysCache pgpKeysCache;

    @Inject
    protected KeysMap keysMap;

    /**
     * <p>
     * Specifies the location of a file that contains the map of dependencies to PGP key.
     * </p>
     *
     * <p>
     * This can be path to local file, path to file on plugin classpath or url address.
     * </p>
     *
     * <p>
     * <a href="keysmap-format.html">Format description.</a>
     * </p>
     *
     * <p>
     * You can use ready keys map: <a href="https://github.com/s4u/pgp-keys-map">https://github.com/s4u/pgp-keys-map</a>
     * </p>
     *
     * @since 1.1.0
     */
    @Parameter(property = "pgpverify.keysMapLocation", defaultValue = "")
    private String keysMapLocation;

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
     * @return Mojo name for current class.
     */
    protected abstract String getMojoName();

    protected abstract void executeConfiguredMojo() throws MojoExecutionException, MojoFailureException;

    private void initPgpKeysCache() throws IOException {
        pgpKeysCache.init(pgpKeysCachePath, pgpKeyServer, pgpKeyServerLoadBalance, proxyName);
    }

    private void initKeysMap() throws ResourceNotFoundException, IOException {
        keysMap.load(keysMapLocation);
    }

    @Override
    public final void execute() throws MojoExecutionException, MojoFailureException {

        if (skip) {
            LOGGER.info("Skipping pgpverify:{}", getMojoName());
            return;
        }

        Try.run(() -> {
            initPgpKeysCache();
            initKeysMap();
        }).getOrElseThrow(e -> new MojoFailureException(e.getMessage(), e));

        executeConfiguredMojo();
    }
}
