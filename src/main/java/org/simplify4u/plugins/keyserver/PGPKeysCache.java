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

package org.simplify4u.plugins.keyserver;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.inject.Inject;
import javax.inject.Named;

import static com.google.common.util.concurrent.Uninterruptibles.sleepUninterruptibly;
import static org.simplify4u.plugins.utils.ExceptionUtils.getMessage;

import io.vavr.control.Try;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.simplify4u.plugins.utils.MavenProxy;
import org.simplify4u.plugins.utils.PGPKeyId;
import org.simplify4u.plugins.utils.PublicKeyUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manage PGP keys local cache.
 *
 * @author Slawomir Jaranowski.
 */
@Named
public class PGPKeysCache {

    private static final Logger LOGGER = LoggerFactory.getLogger(PGPKeysCache.class);
    private static final String NL = System.lineSeparator();

    private static final Pattern KEY_SERVERS_SPLIT_PATTERN = Pattern.compile("[;,\\s]");

    private final MavenProxy mavenProxy;

    private File cachePath;
    private KeyServerList keyServerList;


    private static final Object LOCK = new Object();

    @Inject
    PGPKeysCache(MavenProxy mavenProxy) {
        this.mavenProxy = mavenProxy;
    }

    public void init(File cachePath, String keyServers, boolean loadBalance, String proxyName)
            throws IOException {
        init(cachePath, prepareClients(keyServers, proxyName), loadBalance);
    }

    // used by test
    void init(File cachePath, List<PGPKeysServerClient> pgpKeysServerClients, boolean loadBalance) throws IOException {

        this.cachePath = cachePath;
        this.keyServerList = createKeyServerList(pgpKeysServerClients, loadBalance);

        LOGGER.info("Key server(s) - {}", keyServerList);

        synchronized (LOCK) {
            if (this.cachePath.exists()) {
                if (!this.cachePath.isDirectory()) {
                    throw new IOException("PGP keys cache path exist but is not a directory: " + this.cachePath);
                }
            } else {
                if (this.cachePath.mkdirs()) {
                    LOGGER.info("Create cache directory for PGP keys: {}", this.cachePath);
                } else {
                    throw new IOException("Cache directory create error");
                }
            }
        }
    }

    List<PGPKeysServerClient> prepareClients(String keyServers, String proxyName) {

        List<String> keyServersList = Arrays.stream(KEY_SERVERS_SPLIT_PATTERN.split(keyServers))
                .map(String::trim)
                .filter(s -> s.length() > 0)
                .collect(Collectors.toList());

        return keyServersList.stream()
                .map(keyserver -> Try.of(() ->
                        PGPKeysServerClient.getClient(keyserver, mavenProxy.getProxyByName(proxyName))).get())
                .collect(Collectors.toList());
    }

    static KeyServerList createKeyServerList(List<PGPKeysServerClient> pgpKeysServerClients, boolean loadBalance) {

        if (pgpKeysServerClients == null || pgpKeysServerClients.isEmpty()) {
            throw new IllegalArgumentException("Not allowed empty key server clients list ");
        }

        KeyServerList ret;
        if (pgpKeysServerClients.size() == 1) {
            ret = new KeyServerListOne();
        } else {
            if (loadBalance) {
                ret = new KeyServerListLoadBalance();
            } else {
                ret = new KeyServerListFallback();
            }
        }

        return ret.withClients(pgpKeysServerClients);
    }

    /**
     * URL where PGP key can be watched.
     *
     * @param keyID given keyId
     *
     * @return url from current key server
     */
    public String getUrlForShowKey(PGPKeyId keyID) {
        return keyServerList.getUriForShowKey(keyID).toString();
    }

    public PGPPublicKeyRing getKeyRing(PGPKeyId keyID) throws IOException {


        String path = keyID.getHashPath();
        File keyFile = new File(cachePath, path);

        synchronized (LOCK) {

            if (keyFile.exists()) {
                // load from cache
                Optional<PGPPublicKeyRing> keyRing = loadKeyFromFile(keyFile, keyID);
                if (keyRing.isPresent()) {
                    return keyRing.get();
                }
            }

            // key not exists in cache or something wrong with cache, so receive from servers
            return keyServerList.execute(keysServerClient -> receiveKey(keyFile, keyID, keysServerClient));
        }
    }

    private static Optional<PGPPublicKeyRing> loadKeyFromFile(File keyFile, PGPKeyId keyID)
            throws IOException {
        Optional<PGPPublicKeyRing> keyRing = Optional.empty();
        try (InputStream keyFileStream = new FileInputStream(keyFile)) {
            keyRing = PublicKeyUtils.loadPublicKeyRing(keyFileStream, keyID);
        } catch (PGPException e) {
            throw new IOException(e);
        } finally {
            if (!keyRing.isPresent()) {
                deleteFile(keyFile);
            }
        }
        return keyRing;
    }

    private static PGPPublicKeyRing receiveKey(File keyFile, PGPKeyId keyId, PGPKeysServerClient keysServerClient)
            throws IOException {
        File dir = keyFile.getParentFile();

        if (dir == null) {
            throw new IOException("No parent dir for: " + keyFile);
        }

        if (dir.exists() && !dir.isDirectory()) {
            throw new IOException("Path exist but it isn't directory: " + dir);
        }

        // result is ignored, in this place we suspect that nothing wrong can happen
        // in multi process mode it can happen that two process check for existing directory
        // in the same time, one create it
        dir.mkdirs();

        File partFile = File.createTempFile(String.valueOf(keyId), "pgp-public-key");

        try {
            try (BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(partFile))) {
                keysServerClient.copyKeyToOutputStream(keyId, outputStream, PGPKeysCache::onRetry);
            }
            moveFile(partFile, keyFile);
        } catch (IOException e) {
            // if error try remove file
            deleteFile(keyFile);
            deleteFile(partFile);
            throw e;
        }

        LOGGER.info("Receive key: {}{}\tto {}", keysServerClient.getUriForGetKey(keyId), NL, keyFile);

        // try load key
        return loadKeyFromFile(keyFile, keyId)
                .orElseThrow(() ->
                        new IOException(String.format("Can't find public key %s in download file: %s",
                                keyId, keyFile)));
    }

    private static void onRetry(InetAddress address, int numberOfRetryAttempts, Duration waitInterval,
            Throwable lastThrowable) {

        LOGGER.warn("[Retry #{} waiting: {}] Last address {} with problem: [{}] {}",
                numberOfRetryAttempts, waitInterval, address,
                lastThrowable.getClass().getName(), getMessage(lastThrowable));
    }

    private static void deleteFile(File file) {

        Optional.ofNullable(file)
                .map(File::toPath)
                .ifPresent(filePath ->
                        Try.run(() -> Files.deleteIfExists(filePath))
                                .onFailure(e ->
                                        LOGGER.warn("Can't delete: {} with exception: {}", filePath, e.getMessage())));
    }

    private static void moveFile(File source, File destination) throws IOException {
        try {
            Files.move(source.toPath(), destination.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (FileSystemException fse) {
            // on windows system we can get:
            // The process cannot access the file because it is being used by another process.
            // so wait ... and try again
            sleepUninterruptibly(250L + new SecureRandom().nextInt(1000), TimeUnit.MILLISECONDS);
            Files.move(source.toPath(), destination.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    @FunctionalInterface
    interface KeyServerExecutor {
        PGPPublicKeyRing run(PGPKeysServerClient client) throws IOException;
    }

    /**
     * Abstract class for manage list of key servers.
     */
    abstract static class KeyServerList {

        protected List<PGPKeysServerClient> keysServerClients = new ArrayList<>();
        protected PGPKeysServerClient lastClient;
        protected IOException lastException;

        KeyServerList withClients(List<PGPKeysServerClient> keysServerClients) {
            this.keysServerClients = keysServerClients;
            this.lastClient = keysServerClients.get(0);
            return this;
        }

        URI getUriForShowKey(PGPKeyId keyID) {
            return lastClient.getUriForShowKey(keyID);
        }

        protected Optional<PGPPublicKeyRing> executeWithClient(KeyServerExecutor executor, PGPKeysServerClient client) {
            try {
                Optional<PGPPublicKeyRing> ret = Optional.of(executor.run(client));
                lastClient = client;
                return ret;
            } catch (IOException e) {
                lastException = e;
                LOGGER.warn("{} throw exception: {} - {} try next client", client, getMessage(e), getName());
            }
            return Optional.empty();
        }

        @Override
        public String toString() {
            return String.format("%s list: %s", getName(), keysServerClients);
        }

        abstract String getName();

        abstract PGPPublicKeyRing execute(KeyServerExecutor executor) throws IOException;
    }

    /**
     * Only one key server on list.
     */
    static class KeyServerListOne extends KeyServerList {

        @Override
        String getName() {
            return "one item";
        }

        @Override
        PGPPublicKeyRing execute(KeyServerExecutor executor) throws IOException {
            return executor.run(lastClient);
        }

        @Override
        public String toString() {
            return lastClient.toString();
        }
    }

    /**
     * Always use first server, second only for fallback.
     */
    static class KeyServerListFallback extends KeyServerList {

        @Override
        String getName() {
            return "fallback";
        }

        @Override
        PGPPublicKeyRing execute(KeyServerExecutor executor) throws IOException {

            for (PGPKeysServerClient client : keysServerClients) {
                Optional<PGPPublicKeyRing> pgpPublicKeys = executeWithClient(executor, client);
                if (pgpPublicKeys.isPresent()) {
                    return pgpPublicKeys.get();
                }
            }

            LOGGER.error("All servers from list was failed");
            throw lastException;
        }
    }

    /**
     * Use all server from list, round robin.
     */
    static class KeyServerListLoadBalance extends KeyServerList {

        private int lastIndex = 0;

        @Override
        String getName() {
            return "load balance";
        }

        @Override
        PGPPublicKeyRing execute(KeyServerExecutor executor) throws IOException {

            for (int i = 0; i < keysServerClients.size(); i++) {

                PGPKeysServerClient client = keysServerClients.get(lastIndex);
                lastIndex = (lastIndex + 1) % keysServerClients.size();
                Optional<PGPPublicKeyRing> pgpPublicKeys = executeWithClient(executor, client);
                if (pgpPublicKeys.isPresent()) {
                    return pgpPublicKeys.get();
                }
            }

            LOGGER.error("All servers from list was failed");
            throw lastException;
        }
    }
}
