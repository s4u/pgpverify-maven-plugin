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
import javax.inject.Named;

import static com.google.common.util.concurrent.Uninterruptibles.sleepUninterruptibly;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.simplify4u.plugins.utils.ExceptionUtils.getMessage;

import io.vavr.control.Try;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.simplify4u.plugins.pgp.KeyId;
import org.simplify4u.plugins.pgp.PublicKeyUtils;

/**
 * Manage PGP keys local cache.
 *
 * @author Slawomir Jaranowski.
 */
@Slf4j
@Named
public class PGPKeysCache {

    private static final String NL = System.lineSeparator();
    private static final Object LOCK = new Object();

    private static final Pattern KEY_SERVERS_SPLIT_PATTERN = Pattern.compile("[;,\\s]");

    private File cachePath;
    private int notFoundRefreshHours;
    private KeyServerList keyServerList;

    PGPKeysCache() {
    }

    /**
     * Init Keys cache.
     *
     * @param cacheSettings  a key cache settings
     * @param clientSettings a kay server client settings
     *
     * @throws IOException in case of problems
     */
    public void init(KeyCacheSettings cacheSettings, KeyServerClientSettings clientSettings)
            throws IOException {
        init(cacheSettings, prepareClients(cacheSettings.getKeyServers(), clientSettings));
    }

    // used by test
    void init(KeyCacheSettings cacheSettings, List<PGPKeysServerClient> pgpKeysServerClients) throws IOException {

        this.cachePath = cacheSettings.getCachePath();
        this.notFoundRefreshHours = cacheSettings.getNotFoundRefreshHours();
        this.keyServerList = createKeyServerList(pgpKeysServerClients, cacheSettings.isLoadBalance());

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

    List<PGPKeysServerClient> prepareClients(String keyServers, KeyServerClientSettings clientSettings) {

        List<String> keyServersList = Arrays.stream(KEY_SERVERS_SPLIT_PATTERN.split(keyServers))
                .map(String::trim)
                .filter(s -> s.length() > 0)
                .collect(Collectors.toList());

        return keyServersList.stream()
                .map(keyserver -> Try.of(() ->
                        PGPKeysServerClient.getClient(keyserver, clientSettings)).get())
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
    public String getUrlForShowKey(KeyId keyID) {
        return keyServerList.getUriForShowKey(keyID).toString();
    }

    /**
     * Return Public Key Ring from local cache or from key server.
     *
     * @param keyID a keyId for lookup
     *
     * @return Public Key Ring for given key
     *
     * @throws IOException in case of problems
     */
    public PGPPublicKeyRing getKeyRing(KeyId keyID) throws IOException {

        String path = keyID.getHashPath();
        File keyFile = new File(cachePath, path);

        synchronized (LOCK) {

            checkNotFoundCache(path);

            if (keyFile.exists()) {
                // load from cache
                Optional<PGPPublicKeyRing> keyRing = loadKeyFromFile(keyFile, keyID);
                if (keyRing.isPresent()) {
                    return keyRing.get();
                }
            }

            // key not exists in cache or something wrong with cache, so receive from servers
            return Try.of(() -> keyServerList.execute(keysServerClient -> receiveKey(keyFile, keyID, keysServerClient)))
                    .onFailure(PGPKeyNotFound.class, e -> writeNotFoundCache(path))
                    .get();
        }
    }

    private void writeNotFoundCache(String keyFilePath) {

        File file = new File(cachePath, keyFilePath + ".404");

        try {
            Files.write(file.toPath(), String.valueOf(System.currentTimeMillis()).getBytes(US_ASCII));
        } catch (IOException e) {
            LOGGER.warn("Write file: {} exception: {}", file, getMessage(e));
            deleteFile(file);
        }
    }

    private void checkNotFoundCache(String keyFilePath) throws PGPKeyNotFound {

        File file = new File(cachePath, keyFilePath + ".404");

        if (file.isFile()) {

            long markTime = Try.of(() -> {
                        byte[] cacheContent = Files.readAllBytes(file.toPath());
                        return Long.parseLong(new String(cacheContent, US_ASCII));
                    })
                    .onFailure(e -> LOGGER.warn("Read cache file: {}", file, e))
                    .getOrElse(0L);

            Duration elapsedTime = Duration.ofMillis(System.currentTimeMillis() - markTime);

            if (elapsedTime.toHours() > notFoundRefreshHours) {
                LOGGER.debug("KeyNotFound remove cache {} - mark time: {} elapsed: {}",
                        file, markTime, elapsedTime);
                deleteFile(file);
            } else {
                LOGGER.debug("KeyNotFound from cache {} - mark time: {} elapsed: {}",
                        file, markTime, elapsedTime);
                throw new PGPKeyNotFound();
            }
        }
    }

    private static Optional<PGPPublicKeyRing> loadKeyFromFile(File keyFile, KeyId keyID)
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

    private static PGPPublicKeyRing receiveKey(File keyFile, KeyId keyId, PGPKeysServerClient keysServerClient)
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

        URI getUriForShowKey(KeyId keyID) {
            return lastClient.getUriForShowKey(keyID);
        }

        protected Optional<PGPPublicKeyRing> executeWithClient(KeyServerExecutor executor, PGPKeysServerClient client) {
            try {
                Optional<PGPPublicKeyRing> ret = Optional.of(executor.run(client));
                lastClient = client;
                return ret;
            } catch (IOException e) {
                if (!(lastException instanceof PGPKeyNotFound)) {
                    // if key was not found on one server - don't override
                    lastException = e;
                }
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

            LOGGER.error("All servers from list failed");
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

            LOGGER.error("All servers from list failed");
            throw lastException;
        }
    }
}
