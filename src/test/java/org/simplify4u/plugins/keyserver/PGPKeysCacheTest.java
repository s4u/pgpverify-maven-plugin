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
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.testng.MockitoTestNGListener;
import org.simplify4u.plugins.keyserver.PGPKeysCache.KeyServerList;
import org.simplify4u.plugins.keyserver.PGPKeysCache.KeyServerListFallback;
import org.simplify4u.plugins.keyserver.PGPKeysCache.KeyServerListLoadBalance;
import org.simplify4u.plugins.keyserver.PGPKeysCache.KeyServerListOne;
import org.simplify4u.plugins.utils.PGPKeyId;
import org.simplify4u.plugins.utils.PGPKeyId.PGPKeyIdLong;
import org.simplify4u.sjf4jmock.LoggerMock;
import org.slf4j.Logger;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

@Listeners(MockitoTestNGListener.class)
public class PGPKeysCacheTest {

    public static final PGPKeyId KEY_ID_1 = PGPKeyId.from(1L);

    private Path cachePath;

    @Mock
    private PGPKeysServerClient keysServerClient;

    @InjectMocks
    private PGPKeysCache pgpKeysCache;

    public List<PGPKeysServerClient> prepareKeyServerClient() throws IOException {

        doAnswer(i -> new URI(String.format("https://key.get.example.com/?keyId=%s", (PGPKeyId) i.getArgument(0))))
                .when(keysServerClient).getUriForGetKey(any(PGPKeyId.class));

        doAnswer(i -> {
            try (InputStream inputStream = getClass().getResourceAsStream("/EFE8086F9E93774E.asc")) {
                ByteStreams.copy(inputStream, i.getArgument(1));
            }
            return null;
        }).when(keysServerClient).copyKeyToOutputStream(any(PGPKeyId.class), any(OutputStream.class),
                any(PGPKeysServerClient.OnRetryConsumer.class));

        return Collections.singletonList(keysServerClient);
    }

    @BeforeMethod
    void setup() throws IOException {
        LoggerMock.clearInvocations();
        cachePath = Files.createTempDirectory("cache-path-test");
    }

    @AfterMethod
    void cleanup() throws IOException {
        MoreFiles.deleteRecursively(cachePath, RecursiveDeleteOption.ALLOW_INSECURE);
    }

    @Test
    public void emptyCacheDirShouldBeCreated() throws IOException {

        File emptyCachePath = new File(cachePath.toFile(), "empty");

        assertThat(emptyCachePath).doesNotExist();

        pgpKeysCache.init(emptyCachePath, Collections.singletonList(keysServerClient), true);

        assertThat(emptyCachePath)
                .exists()
                .isDirectory();
    }

    @Test
    public void fileAsCacheDirThrowException() throws IOException {

        File fileAsCachePath = new File(cachePath.toFile(), "file.tmp");
        MoreFiles.touch(fileAsCachePath.toPath());

        assertThat(fileAsCachePath)
                .exists()
                .isFile();

        assertThatCode(() -> pgpKeysCache.init(fileAsCachePath, Collections.singletonList(keysServerClient), true))
                .isExactlyInstanceOf(IOException.class)
                .hasMessageStartingWith("PGP keys cache path exist but is not a directory:");
    }

    @Test
    public void getKeyFromCache() throws IOException, PGPException {

        List<PGPKeysServerClient> keysServerClients = prepareKeyServerClient();
        pgpKeysCache.init(cachePath.toFile(), keysServerClients, true);

        // first call retrieve key from server
        PGPPublicKeyRing keyRing = pgpKeysCache.getKeyRing(PGPKeyId.from(0xEFE8086F9E93774EL));

        assertThat(keyRing)
                .hasSize(2)
                .anyMatch(key -> key.getKeyID() == 0xEFE8086F9E93774EL);

        verify(keysServerClients.get(0)).getUriForGetKey(any(PGPKeyId.class));
        verify(keysServerClients.get(0)).copyKeyToOutputStream(any(PGPKeyIdLong.class), any(OutputStream.class), any(PGPKeysServerClient.OnRetryConsumer.class));
        verifyNoMoreInteractions(keysServerClients.get(0));
        clearInvocations(keysServerClients.get(0));

        // second from cache
        keyRing = pgpKeysCache.getKeyRing(PGPKeyId.from(0xEFE8086F9E93774EL));

        assertThat(keyRing)
                .hasSize(2)
                .anyMatch(key -> key.getKeyID() == 0xEFE8086F9E93774EL);

        verifyNoInteractions(keysServerClients.get(0));
    }

    @Test
    public void nonExistingKeyInRingThrowException() throws IOException, PGPException {

        List<PGPKeysServerClient> keysServerClients = prepareKeyServerClient();
        pgpKeysCache.init(cachePath.toFile(), keysServerClients, true);

        // first call retrieve key from server
        assertThatCode(() -> pgpKeysCache.getKeyRing(PGPKeyId.from(0x1234567890L)))
                .isExactlyInstanceOf(PGPException.class)
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
            serverList.execute(client -> {
                client.copyKeyToOutputStream(KEY_ID_1, null, null);
                executedClient.add(client);
            });
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
                serverListFallback.execute(client ->
                        client.copyKeyToOutputStream(KEY_ID_1, null, null)))
                .isExactlyInstanceOf(IOException.class)
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
            serverListFallback.execute(client -> {
                client.copyKeyToOutputStream(KEY_ID_1, null, null);
                executedClient.add(client);
            });
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
            serverListFallback.execute(client -> {
                client.copyKeyToOutputStream(KEY_ID_1, null, null);
                executedClient.add(client);
            });
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
    public Object[] keyServerListWithFallBack() {

        return new Object[]{
                new KeyServerListFallback(),
                new KeyServerListLoadBalance()
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
            keyServerList.execute(client -> {
                client.copyKeyToOutputStream(KEY_ID_1, null, null);
                executedClient.add(client);
            });
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
                keyServerList.execute(client ->
                        client.copyKeyToOutputStream(KEY_ID_1, null, null)))
                .isExactlyInstanceOf(IOException.class)
                .hasMessage("Fallback test2");

        Logger keysCacheLogger = LoggerMock.getLoggerMock(PGPKeysCache.class);
        verify(keysCacheLogger).warn(eq("{} throw exception: {} - {} try next client"), eq(client1), eq("Fallback test1"), anyString());
        verify(keysCacheLogger).warn(eq("{} throw exception: {} - {} try next client"), eq(client2), eq("Fallback test2"), anyString());
        verify(keysCacheLogger).error("All servers from list was failed");
        verifyNoMoreInteractions(keysCacheLogger);

        verify(client1).copyKeyToOutputStream(KEY_ID_1, null, null);
        verifyNoMoreInteractions(client1);

        verify(client2).copyKeyToOutputStream(KEY_ID_1, null, null);
        verifyNoMoreInteractions(client2);
    }

    @Test(dataProvider = "keyServerListWithFallBack")
    public void throwsPGPKeyNotFoundWhenKeyNotFoundOnAnyServer(KeyServerList keyServerList) throws IOException {

        PGPKeysServerClient client1 = mock(PGPKeysServerClient.class);
        PGPKeysServerClient client2 = mock(PGPKeysServerClient.class);

        doThrow(new PGPKeyNotFound()).when(client1).copyKeyToOutputStream(KEY_ID_1, null, null);
        doThrow(new PGPKeyNotFound()).when(client2).copyKeyToOutputStream(KEY_ID_1, null, null);

        keyServerList.withClients(Arrays.asList(client1, client2));

        assertThatCode(() ->
                keyServerList.execute(client ->
                        client.copyKeyToOutputStream(KEY_ID_1, null, null)))
                .isExactlyInstanceOf(PGPKeyNotFound.class);

        Logger keysCacheLogger = LoggerMock.getLoggerMock(PGPKeysCache.class);
        verify(keysCacheLogger).warn(eq("{} throw exception: {} - {} try next client"), eq(client1), isNull(), anyString());
        verify(keysCacheLogger).warn(eq("{} throw exception: {} - {} try next client"), eq(client2), isNull(), anyString());
        verify(keysCacheLogger).error("All servers from list was failed");
        verifyNoMoreInteractions(keysCacheLogger);

        verify(client1).copyKeyToOutputStream(KEY_ID_1, null, null);
        verifyNoMoreInteractions(client1);

        verify(client2).copyKeyToOutputStream(KEY_ID_1, null, null);
        verifyNoMoreInteractions(client2);
    }
}
