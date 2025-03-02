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
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.inject.Named;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.simplify4u.plugins.utils.ExceptionUtils.getMessage;

import io.vavr.control.Try;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openpgp.PGPException;
import org.simplify4u.plugins.pgp.KeyId;
import org.simplify4u.plugins.pgp.PublicKeyRingPack;
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
    private boolean offLine;

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
        this.offLine = cacheSettings.isOffLine();

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
                .filter(s -> !s.isEmpty())
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
     * @return Public Key Ring for given key
     * @throws IOException in case of problems
     */
    public PublicKeyRingPack getKeyRing(KeyId keyID) throws IOException {

        String path = keyID.getHashPath();
        Path keyFile = new File(cachePath, path).toPath();

        synchronized (LOCK) {

            if (!offLine) {
                checkNotFoundCache(path);
            }

            if (keyFile.toFile().exists()) {
                // load from cache
                PublicKeyRingPack keyRing = loadKeyFromFile(keyFile, keyID);
                if (!keyRing.isEmpty()) {
                    return keyRing;
                }
            }

            if (offLine) {
                throw new IOException("Key " + keyID + " not exits in cache under path: " + keyFile
                        + " it is not possible to download in offline mode");
            }

            // key not exists in cache or something wrong with cache, so receive from servers
            return Try.of(() -> keyServerList.execute(keysServerClient -> receiveKey(keyFile, keyID, keysServerClient)))
                    .onFailure(PGPKeyNotFound.class, e -> writeNotFoundCache(path))
                    .get();
        }
    }

    private void writeNotFoundCache(String keyFilePath) {

        Path file = new File(cachePath, keyFilePath + ".404").toPath();

        try {
            Files.write(file, String.valueOf(System.currentTimeMillis()).getBytes(US_ASCII));
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
                deleteFile(file.toPath());
            } else {
                LOGGER.debug("KeyNotFound from cache {} - mark time: {} elapsed: {}",
                        file, markTime, elapsedTime);
                throw new PGPKeyNotFound();
            }
        }
    }

    private static PublicKeyRingPack loadKeyFromFile(Path keyFile, KeyId keyID)
            throws IOException {
        PublicKeyRingPack keyRing = PublicKeyRingPack.EMPTY;
        try (InputStream keyFileStream = Files.newInputStream(keyFile)) {
            keyRing = PublicKeyUtils.loadPublicKeyRing(keyFileStream, keyID);
        } catch (PGPException e) {
            throw new IOException(e);
        } finally {
            if (keyRing.isEmpty()) {
                deleteFile(keyFile);
            }
        }
        return keyRing;
    }

    private static PublicKeyRingPack receiveKey(Path keyFile, KeyId keyId, PGPKeysServerClient keysServerClient)
            throws IOException {
        Path dir = keyFile.getParent();

        if (dir == null) {
            throw new IOException("No parent dir for: " + keyFile);
        }

        if (dir.toFile().exists() && !dir.toFile().isDirectory()) {
            throw new IOException("Path exist but it isn't directory: " + dir);
        }

        Files.createDirectories(dir);

        Path partFile = Files.createTempFile(String.valueOf(keyId), "pgp-public-key");

        try {
            try (BufferedOutputStream output = new BufferedOutputStream(Files.newOutputStream(partFile))) {
                keysServerClient.copyKeyToOutputStream(keyId, output, PGPKeysCache::onRetry);
            }
            moveFile(partFile, keyFile);
        } catch (IOException e) {
            // if error try to remove file
            deleteFile(keyFile);
            deleteFile(partFile);
            throw e;
        }

        LOGGER.info("Receive key: {}{}\tto {}", keysServerClient.getUriForGetKey(keyId), NL, keyFile);

        // try load key
        PublicKeyRingPack keyRingPack = loadKeyFromFile(keyFile, keyId);
        if (keyRingPack.isEmpty()) {
            throw new IOException(String.format("Can't find public key %s in download file: %s", keyId, keyFile));
        }
        return keyRingPack;
    }

    private static void onRetry(InetAddress address, int numberOfRetryAttempts, Duration waitInterval,
            Throwable lastThrowable) {

        LOGGER.warn("[Retry #{} waiting: {}] Last address {} with problem: [{}] {}",
                numberOfRetryAttempts, waitInterval, address,
                lastThrowable.getClass().getName(), getMessage(lastThrowable));
    }

    private static void deleteFile(Path file) {

        Optional.ofNullable(file)
                .ifPresent(filePath ->
                        Try.run(() -> Files.deleteIfExists(filePath))
                                .onFailure(e ->
                                        LOGGER.warn("Can't delete: {} with exception: {}", filePath, e.getMessage())));
    }

    private static void moveFile(Path source, Path destination) throws IOException {
        try {
            Files.move(source, destination, StandardCopyOption.REPLACE_EXISTING);
        } catch (FileSystemException fse) {
            // on Windows system we can get:
            // The process cannot access the file because it is being used by another process.
            // so wait ... and try again
            try {
                Thread.sleep(250L + new SecureRandom().nextInt(1000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            Files.move(source, destination, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    @FunctionalInterface
    interface KeyServerExecutor {
        PublicKeyRingPack run(PGPKeysServerClient client) throws IOException;
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

        protected PublicKeyRingPack executeWithClient(KeyServerExecutor executor, PGPKeysServerClient client) {
            try {
                PublicKeyRingPack ret = executor.run(client);
                lastClient = client;
                return ret;
            } catch (IOException e) {
                if (!(lastException instanceof PGPKeyNotFound)) {
                    // if key was not found on one server - don't override
                    lastException = e;
                }
                LOGGER.warn("{} throw exception: {} - {} try next client", client, getMessage(e), getName());
            }
            return PublicKeyRingPack.EMPTY;
        }

        @Override
        public String toString() {
            return String.format("%s list: %s", getName(), keysServerClients);
        }

        abstract String getName();

        abstract PublicKeyRingPack execute(KeyServerExecutor executor) throws IOException;
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
        PublicKeyRingPack execute(KeyServerExecutor executor) throws IOException {
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
        PublicKeyRingPack execute(KeyServerExecutor executor) throws IOException {

            for (PGPKeysServerClient client : keysServerClients) {
                PublicKeyRingPack pgpPublicKeys = executeWithClient(executor, client);
                if (!pgpPublicKeys.isEmpty()) {
                    return pgpPublicKeys;
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
        PublicKeyRingPack execute(KeyServerExecutor executor) throws IOException {

            for (int i = 0; i < keysServerClients.size(); i++) {

                PGPKeysServerClient client = keysServerClients.get(lastIndex);
                lastIndex = (lastIndex + 1) % keysServerClients.size();
                PublicKeyRingPack pgpPublicKeys = executeWithClient(executor, client);
                if (!pgpPublicKeys.isEmpty()) {
                    return pgpPublicKeys;
                }
            }

            LOGGER.error("All servers from list failed");
            throw lastException;
        }
    }
}
