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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import com.google.common.io.ByteStreams;
import com.google.common.io.MoreFiles;
import com.google.common.io.RecursiveDeleteOption;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.testng.MockitoTestNGListener;
import org.simplify4u.plugins.keyserver.PGPKeysCache.KeyServerList;
import org.simplify4u.plugins.keyserver.PGPKeysCache.KeyServerListFallback;
import org.simplify4u.plugins.keyserver.PGPKeysCache.KeyServerListLoadBalance;
import org.simplify4u.plugins.keyserver.PGPKeysCache.KeyServerListOne;
import org.simplify4u.plugins.pgp.KeyId;
import org.simplify4u.plugins.pgp.KeyId.KeyIdLong;
import org.slf4j.Logger;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

@Listeners(MockitoTestNGListener.class)
public class PGPKeysCacheTest {

    public static final KeyId KEY_ID_1 = KeyId.from(1L);

    private Path cachePath;

    @Spy
    Logger keysCacheLogger;

    @Mock
    private PGPPublicKeyRing emptyPgpPublicKeyRing;

    @Mock
    private PGPKeysServerClient keysServerClient;

    @InjectMocks
    private PGPKeysCache pgpKeysCache;

    private List<PGPKeysServerClient> prepareKeyServerClient() throws IOException {

        doAnswer(i -> new URI(String.format("https://key.get.example.com/?keyId=%s", (KeyId) i.getArgument(0))))
                .when(keysServerClient).getUriForGetKey(any(KeyId.class));

        doAnswer(i -> {
            try (InputStream inputStream = getClass().getResourceAsStream("/EFE8086F9E93774E.asc")) {
                ByteStreams.copy(inputStream, i.getArgument(1));
            }
            return null;
        }).when(keysServerClient).copyKeyToOutputStream(any(KeyId.class), any(OutputStream.class),
                any(PGPKeysServerClient.OnRetryConsumer.class));

        return Collections.singletonList(keysServerClient);
    }

    private List<PGPKeysServerClient> prepareKeyServerClientWithNotFound() throws IOException {

        doThrow(new PGPKeyNotFound())
                .when(keysServerClient).copyKeyToOutputStream(any(KeyId.class), any(OutputStream.class),
                        any(PGPKeysServerClient.OnRetryConsumer.class));

        return Collections.singletonList(keysServerClient);
    }

    @BeforeMethod
    void setup() throws IOException {
        cachePath = Files.createTempDirectory("cache-path-test");
    }

    @AfterMethod
    void cleanup() throws IOException {
        MoreFiles.deleteRecursively(cachePath, RecursiveDeleteOption.ALLOW_INSECURE);
    }

    @Test
    public void emptyCacheDirShouldBeCreated() throws IOException {

        File emptyCachePath = new File(cachePath.toFile(), "empty");

        KeyCacheSettings cacheSettings = KeyCacheSettings.builder()
                .cachePath(emptyCachePath)
                .build();

        assertThat(emptyCachePath).doesNotExist();

        pgpKeysCache.init(cacheSettings, Collections.singletonList(keysServerClient));

        assertThat(emptyCachePath)
                .exists()
                .isDirectory();
    }

    @Test
    public void fileAsCacheDirThrowException() throws IOException {

        File fileAsCachePath = new File(cachePath.toFile(), "file.tmp");
        MoreFiles.touch(fileAsCachePath.toPath());

        KeyCacheSettings cacheSettings = KeyCacheSettings.builder()
                .cachePath(fileAsCachePath)
                .build();

        assertThat(fileAsCachePath)
                .exists()
                .isFile();

        assertThatCode(() -> pgpKeysCache.init(cacheSettings, Collections.singletonList(keysServerClient)))
                .isExactlyInstanceOf(IOException.class)
                .hasMessageStartingWith("PGP keys cache path exist but is not a directory:");
    }

    @Test
    public void getKeyFromCache() throws IOException {

        List<PGPKeysServerClient> keysServerClients = prepareKeyServerClient();

        KeyCacheSettings cacheSettings = KeyCacheSettings.builder()
                .cachePath(cachePath.toFile())
                .build();

        pgpKeysCache.init(cacheSettings, keysServerClients);

        // first call retrieve key from server
        PGPPublicKeyRing keyRing = pgpKeysCache.getKeyRing(KeyId.from(0xEFE8086F9E93774EL));

        assertThat(keyRing)
                .hasSize(2)
                .anyMatch(key -> key.getKeyID() == 0xEFE8086F9E93774EL);

        verify(keysServerClients.get(0)).getUriForGetKey(any(KeyId.class));
        verify(keysServerClients.get(0)).copyKeyToOutputStream(any(KeyIdLong.class), any(OutputStream.class), any(PGPKeysServerClient.OnRetryConsumer.class));
        verifyNoMoreInteractions(keysServerClients.get(0));
        clearInvocations(keysServerClients.get(0));

        // second from cache
        keyRing = pgpKeysCache.getKeyRing(KeyId.from(0xEFE8086F9E93774EL));

        assertThat(keyRing)
                .hasSize(2)
                .anyMatch(key -> key.getKeyID() == 0xEFE8086F9E93774EL);

        verifyNoInteractions(keysServerClients.get(0));
    }

    @Test
    public void notFoundKeyFromCache() throws IOException {
        List<PGPKeysServerClient> keysServerClients = prepareKeyServerClientWithNotFound();

        KeyCacheSettings cacheSettings = KeyCacheSettings.builder()
                .cachePath(cachePath.toFile())
                .build();

        pgpKeysCache.init(cacheSettings, keysServerClients);

        KeyId keyId = KeyId.from(0x1234567890L);

        // first call create file with 404 extension in cache
        assertThatCode(() -> pgpKeysCache.getKeyRing(keyId))
                .isExactlyInstanceOf(PGPKeyNotFound.class);

        File notFoundCache = new File(cachePath.toFile(), keyId.getHashPath() + ".404");

        assertThat(notFoundCache)
                .content()
                .containsOnlyDigits();

        // second call should use cache
        assertThatCode(() -> pgpKeysCache.getKeyRing(keyId))
                .isExactlyInstanceOf(PGPKeyNotFound.class);

        // client was call only once
        verify(keysServerClients.get(0)).copyKeyToOutputStream(eq(keyId), any(), any());
    }

    @Test
    public void notFoundKeyCacheShouldBeEvicted() throws IOException {
        List<PGPKeysServerClient> keysServerClients = prepareKeyServerClientWithNotFound();

        KeyCacheSettings cacheSettings = KeyCacheSettings.builder()
                .cachePath(cachePath.toFile())
                .notFoundRefreshHours(1)
                .build();

        pgpKeysCache.init(cacheSettings, keysServerClients);

        KeyId keyId = KeyId.from(0x1234567890L);

        // first call create file with 404 extension in cache
        assertThatCode(() -> pgpKeysCache.getKeyRing(keyId))
                .isExactlyInstanceOf(PGPKeyNotFound.class);

        File notFoundCache = new File(cachePath.toFile(), keyId.getHashPath() + ".404");

        assertThat(notFoundCache)
                .content()
                .containsOnlyDigits();

        // last check 2 hour ago
        String lastHitTime = String.valueOf(System.currentTimeMillis() - (120 * 60 * 1000));
        Files.write(notFoundCache.toPath(), lastHitTime.getBytes());

        // second call should call client
        assertThatCode(() -> pgpKeysCache.getKeyRing(keyId))
                .isExactlyInstanceOf(PGPKeyNotFound.class);

        // cache file was changed
        assertThat(notFoundCache).content()
                .containsOnlyDigits()
                .isNotEqualTo(lastHitTime);

        // client was call twice
        verify(keysServerClients.get(0), times(2)).copyKeyToOutputStream(eq(keyId), any(), any());
    }

    @Test
    public void notFoundCacheEmptyFileShouldNotBreakProcessing() throws IOException {

        List<PGPKeysServerClient> keysServerClients = prepareKeyServerClientWithNotFound();

        KeyCacheSettings cacheSettings = KeyCacheSettings.builder()
                .cachePath(cachePath.toFile())
                .build();

        pgpKeysCache.init(cacheSettings, keysServerClients);

        KeyId keyId = KeyId.from(0x1234567890L);

        // create empty cache file
        File notFoundCache = new File(cachePath.toFile(), keyId.getHashPath() + ".404");
        notFoundCache.getParentFile().mkdirs();
        notFoundCache.createNewFile();

        assertThat(notFoundCache).isEmpty();

        // call create file with 404 extension in cache
        assertThatCode(() -> pgpKeysCache.getKeyRing(keyId))
                .isExactlyInstanceOf(PGPKeyNotFound.class);

        // empty file should be replaced by one with correct data
        assertThat(notFoundCache)
                .content()
                .containsOnlyDigits();

        // client was call
        verify(keysServerClients.get(0)).copyKeyToOutputStream(eq(keyId), any(), any());
    }

    @Test
    public void brokenKeyInCache() throws IOException {

        KeyCacheSettings cacheSettings = KeyCacheSettings.builder()
                .cachePath(cachePath.toFile())
                .build();

        List<PGPKeysServerClient> keysServerClients = prepareKeyServerClient();
        pgpKeysCache.init(cacheSettings, keysServerClients);

        // create empty file for key in cache
        Path keyDirPath = cachePath.resolve("EF").resolve("E8");
        Files.createDirectories(keyDirPath);
        Files.createFile(keyDirPath.resolve("EFE8086F9E93774E.asc"));

        // call should retrieve key from server
        PGPPublicKeyRing keyRing = pgpKeysCache.getKeyRing(KeyId.from(0xEFE8086F9E93774EL));

        assertThat(keyRing)
                .hasSize(2)
                .anyMatch(key -> key.getKeyID() == 0xEFE8086F9E93774EL);

        verify(keysServerClients.get(0)).getUriForGetKey(any(KeyId.class));
        verify(keysServerClients.get(0)).copyKeyToOutputStream(any(KeyIdLong.class), any(OutputStream.class), any(PGPKeysServerClient.OnRetryConsumer.class));
        verifyNoMoreInteractions(keysServerClients.get(0));
        clearInvocations(keysServerClients.get(0));
    }

    @Test
    public void nonExistingKeyInRingThrowException() throws IOException {

        List<PGPKeysServerClient> keysServerClients = prepareKeyServerClient();

        KeyCacheSettings cacheSettings = KeyCacheSettings.builder()
                .cachePath(cachePath.toFile())
                .build();

        pgpKeysCache.init(cacheSettings, keysServerClients);

        // first call retrieve key from server
        assertThatCode(() -> pgpKeysCache.getKeyRing(KeyId.from(0x1234567890L)))
                .isExactlyInstanceOf(IOException.class)
                .hasMessageStartingWith("Can't find public key 0x0000001234567890 in download file:");
    }

    @DataProvider(name = "serverListTestData")
    public Object[][] serverListTestData() {

        PGPKeysServerClient client1 = mock(PGPKeysServerClient.class);
        PGPKeysServerClient client2 = mock(PGPKeysServerClient.class);

        return new Object[][]{
                {Collections.singletonList(client1), true, KeyServerListOne.class},
                {Collections.singletonList(client1), false, KeyServerListOne.class},
                {Arrays.asList(client1, client2), true, KeyServerListLoadBalance.class},
                {Arrays.asList(client1, client2), false, KeyServerListFallback.class}
        };
    }

    @Test(dataProvider = "serverListTestData")
    public void createKeyServerListReturnCorrectImplementation(
            List<PGPKeysServerClient> serverList, boolean loadBalance, Class<? extends KeyServerList> aClass) {

        KeyServerList keyServerList = PGPKeysCache.createKeyServerList(serverList, loadBalance);

        assertThat(keyServerList).isExactlyInstanceOf(aClass);
    }

    @Test
    public void listOneUseFirstServerForCorrectExecute() throws IOException {

        PGPKeysServerClient client1 = mock(PGPKeysServerClient.class);
        PGPKeysServerClient client2 = mock(PGPKeysServerClient.class);

        List<PGPKeysServerClient> executedClient = new ArrayList<>();

        KeyServerList serverList = new KeyServerListOne().withClients(Arrays.asList(client1, client2));

        for (int i = 0; i < 2; i++) {
            PGPPublicKeyRing publicKeyRing = serverList.execute(client -> {
                client.copyKeyToOutputStream(KEY_ID_1, null, null);
                executedClient.add(client);
                return emptyPgpPublicKeyRing;
            });
            assertThat(publicKeyRing).isSameAs(emptyPgpPublicKeyRing);
            serverList.getUriForShowKey(KEY_ID_1);
        }

        assertThat(executedClient).containsOnly(client1, client1);
        verify(client1, times(2)).copyKeyToOutputStream(KEY_ID_1, null, null);
        verify(client1, times(2)).getUriForShowKey(KEY_ID_1);
        verifyNoMoreInteractions(client1);
        verifyNoInteractions(client2);
    }

    @Test
    public void listOneThrowsExceptionForFailedExecute() throws IOException {

        PGPKeysServerClient client1 = mock(PGPKeysServerClient.class);
        PGPKeysServerClient client2 = mock(PGPKeysServerClient.class);

        doThrow(new IOException("Fallback test")).when(client1).copyKeyToOutputStream(KEY_ID_1, null, null);

        KeyServerList serverListFallback = new KeyServerListOne().withClients(Arrays.asList(client1, client2));

        assertThatCode(() ->
                serverListFallback.execute(client -> {
                    client.copyKeyToOutputStream(KEY_ID_1, null, null);
                    return null;
                })
        ).isExactlyInstanceOf(IOException.class)
                .hasMessage("Fallback test");

        verify(client1).copyKeyToOutputStream(KEY_ID_1, null, null);
        verifyNoMoreInteractions(client1);
        verifyNoInteractions(client2);
    }

    @Test
    public void fallbackOnlyUseFirstServerForCorrectExecute() throws IOException {

        PGPKeysServerClient client1 = mock(PGPKeysServerClient.class);
        PGPKeysServerClient client2 = mock(PGPKeysServerClient.class);

        List<PGPKeysServerClient> executedClient = new ArrayList<>();

        KeyServerList serverListFallback = new KeyServerListFallback().withClients(Arrays.asList(client1, client2));

        for (int i = 0; i < 2; i++) {
            PGPPublicKeyRing publicKeyRing = serverListFallback.execute(client -> {
                client.copyKeyToOutputStream(KEY_ID_1, null, null);
                executedClient.add(client);
                return emptyPgpPublicKeyRing;
            });
            assertThat(publicKeyRing).isSameAs(emptyPgpPublicKeyRing);
            serverListFallback.getUriForShowKey(KEY_ID_1);
        }

        assertThat(executedClient).containsOnly(client1, client1);
        verify(client1, times(2)).copyKeyToOutputStream(KEY_ID_1, null, null);
        verify(client1, times(2)).getUriForShowKey(KEY_ID_1);
        verifyNoMoreInteractions(client1);
        verifyNoInteractions(client2);
    }

    @Test
    public void loadBalanceIterateByAllServer() throws IOException {

        PGPKeysServerClient client1 = mock(PGPKeysServerClient.class);
        PGPKeysServerClient client2 = mock(PGPKeysServerClient.class);

        List<PGPKeysServerClient> executedClient = new ArrayList<>();

        KeyServerList serverListFallback = new KeyServerListLoadBalance().withClients(Arrays.asList(client1, client2));

        for (int i = 0; i < 3; i++) {
            PGPPublicKeyRing publicKeyRing = serverListFallback.execute(client -> {
                client.copyKeyToOutputStream(KEY_ID_1, null, null);
                executedClient.add(client);
                return emptyPgpPublicKeyRing;
            });
            assertThat(publicKeyRing).isSameAs(emptyPgpPublicKeyRing);
            serverListFallback.getUriForShowKey(KEY_ID_1);
        }

        assertThat(executedClient).containsExactly(client1, client2, client1);

        verify(client1, times(2)).copyKeyToOutputStream(KEY_ID_1, null, null);
        verify(client1, times(2)).getUriForShowKey(KEY_ID_1);
        verifyNoMoreInteractions(client1);

        verify(client2).copyKeyToOutputStream(KEY_ID_1, null, null);
        verify(client2).getUriForShowKey(KEY_ID_1);
        verifyNoMoreInteractions(client1);
    }

    @DataProvider(name = "keyServerListWithFallBack")
    public Object[][] keyServerListWithFallBack() {

        return new Object[][]{
                {new KeyServerListFallback()},
                {new KeyServerListLoadBalance()}
        };
    }

    @Test(dataProvider = "keyServerListWithFallBack")
    public void useSecondServerForFailedExecute(KeyServerList keyServerList) throws IOException {

        PGPKeysServerClient client1 = mock(PGPKeysServerClient.class);
        PGPKeysServerClient client2 = mock(PGPKeysServerClient.class);

        doThrow(new IOException("Fallback test")).when(client1).copyKeyToOutputStream(KEY_ID_1, null, null);

        keyServerList.withClients(Arrays.asList(client1, client2));

        List<PGPKeysServerClient> executedClient = new ArrayList<>();

        for (int i = 0; i < 2; i++) {
            PGPPublicKeyRing publicKeyRing = keyServerList.execute(client -> {
                client.copyKeyToOutputStream(KEY_ID_1, null, null);
                executedClient.add(client);
                return emptyPgpPublicKeyRing;
            });
            assertThat(publicKeyRing).isSameAs(emptyPgpPublicKeyRing);
            keyServerList.getUriForShowKey(KEY_ID_1);
        }

        assertThat(executedClient).containsExactly(client2, client2);

        verify(client1, times(2)).copyKeyToOutputStream(KEY_ID_1, null, null);
        verifyNoMoreInteractions(client1);

        verify(client2, times(2)).copyKeyToOutputStream(KEY_ID_1, null, null);
        verify(client2, times(2)).getUriForShowKey(KEY_ID_1);

        verifyNoMoreInteractions(client2);
    }

    @Test(dataProvider = "keyServerListWithFallBack")
    public void throwsExceptionForAllFailedExecute(KeyServerList keyServerList) throws IOException {

        PGPKeysServerClient client1 = mock(PGPKeysServerClient.class);
        PGPKeysServerClient client2 = mock(PGPKeysServerClient.class);

        doThrow(new IOException("Fallback test1")).when(client1).copyKeyToOutputStream(KEY_ID_1, null, null);
        doThrow(new IOException("Fallback test2")).when(client2).copyKeyToOutputStream(KEY_ID_1, null, null);

        keyServerList.withClients(Arrays.asList(client1, client2));

        assertThatCode(() ->
                keyServerList.execute(client -> {
                    client.copyKeyToOutputStream(KEY_ID_1, null, null);
                    return null;
                })
        ).isExactlyInstanceOf(IOException.class)
                .hasMessage("Fallback test2");

        verify(keysCacheLogger).warn(eq("{} throw exception: {} - {} try next client"), eq(client1), eq("Fallback test1"), anyString());
        verify(keysCacheLogger).warn(eq("{} throw exception: {} - {} try next client"), eq(client2), eq("Fallback test2"), anyString());
        verify(keysCacheLogger).error("All servers from list failed");
        verifyNoMoreInteractions(keysCacheLogger);

        verify(client1).copyKeyToOutputStream(KEY_ID_1, null, null);
        verifyNoMoreInteractions(client1);

        verify(client2).copyKeyToOutputStream(KEY_ID_1, null, null);
        verifyNoMoreInteractions(client2);
    }

    @Test(dataProvider = "keyServerListWithFallBack")
    public void throwsPGPKeyNotFoundWhenKeyNotFoundOnLastServer(KeyServerList keyServerList) throws IOException {

        PGPKeysServerClient client1 = mock(PGPKeysServerClient.class);
        PGPKeysServerClient client2 = mock(PGPKeysServerClient.class);

        doThrow(new IOException()).when(client1).copyKeyToOutputStream(KEY_ID_1, null, null);
        doThrow(new PGPKeyNotFound()).when(client2).copyKeyToOutputStream(KEY_ID_1, null, null);

        keyServerList.withClients(Arrays.asList(client1, client2));

        assertThatCode(() ->
                keyServerList.execute(client -> {
                    client.copyKeyToOutputStream(KEY_ID_1, null, null);
                    return null;
                })
        ).isExactlyInstanceOf(PGPKeyNotFound.class);

        verify(keysCacheLogger).warn(eq("{} throw exception: {} - {} try next client"), eq(client1), isNull(), anyString());
        verify(keysCacheLogger).warn(eq("{} throw exception: {} - {} try next client"), eq(client2), isNull(), anyString());
        verify(keysCacheLogger).error("All servers from list failed");
        verifyNoMoreInteractions(keysCacheLogger);

        verify(client1).copyKeyToOutputStream(KEY_ID_1, null, null);
        verifyNoMoreInteractions(client1);

        verify(client2).copyKeyToOutputStream(KEY_ID_1, null, null);
        verifyNoMoreInteractions(client2);
    }

    @Test(dataProvider = "keyServerListWithFallBack")
    public void throwsPGPKeyNotFoundWhenKeyNotFoundOnFirstServer(KeyServerList keyServerList) throws IOException {

        PGPKeysServerClient client1 = mock(PGPKeysServerClient.class);
        PGPKeysServerClient client2 = mock(PGPKeysServerClient.class);

        doThrow(new PGPKeyNotFound()).when(client1).copyKeyToOutputStream(KEY_ID_1, null, null);
        doThrow(new IOException()).when(client2).copyKeyToOutputStream(KEY_ID_1, null, null);

        keyServerList.withClients(Arrays.asList(client1, client2));

        assertThatCode(() ->
                keyServerList.execute(client -> {
                    client.copyKeyToOutputStream(KEY_ID_1, null, null);
                    return null;
                })
        ).isExactlyInstanceOf(PGPKeyNotFound.class);

        verify(keysCacheLogger).warn(eq("{} throw exception: {} - {} try next client"), eq(client1), isNull(), anyString());
        verify(keysCacheLogger).warn(eq("{} throw exception: {} - {} try next client"), eq(client2), isNull(), anyString());
        verify(keysCacheLogger).error("All servers from list failed");
        verifyNoMoreInteractions(keysCacheLogger);

        verify(client1).copyKeyToOutputStream(KEY_ID_1, null, null);
        verifyNoMoreInteractions(client1);

        verify(client2).copyKeyToOutputStream(KEY_ID_1, null, null);
        verifyNoMoreInteractions(client2);
    }
}
