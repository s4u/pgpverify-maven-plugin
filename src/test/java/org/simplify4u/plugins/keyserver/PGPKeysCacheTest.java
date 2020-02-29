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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import com.google.common.io.ByteStreams;
import com.google.common.io.MoreFiles;
import com.google.common.io.RecursiveDeleteOption;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class PGPKeysCacheTest {

    private Path cachePath;
    private PGPKeysServerClient keysServerClient;

    @BeforeMethod
    public void setup() throws IOException {
        cachePath = Files.createTempDirectory("cache-path-test");
        keysServerClient = mock(PGPKeysServerClient.class);

        doAnswer(i -> new URI(String.format("https://key.get.example.com/?keyId=%016x", (long) i.getArgument(0))))
                .when(keysServerClient).getUriForGetKey(anyLong());


        doAnswer(i -> {
            try (InputStream inputStream = getClass().getResourceAsStream("/EFE8086F9E93774E.asc")) {
                ByteStreams.copy(inputStream, i.getArgument(1));
            }
            return null;
        }).when(keysServerClient).copyKeyToOutputStream(anyLong(), any(OutputStream.class), any(PGPKeysServerClient.OnRetryConsumer.class));
    }

    @AfterMethod
    public void cleanup() throws IOException {
        MoreFiles.deleteRecursively(cachePath, RecursiveDeleteOption.ALLOW_INSECURE);
    }

    @Test
    public void emptyCacheDirShouldBeCreated() throws IOException {

        File emptyCachePath = new File(cachePath.toFile(), "empty");

        assertThat(emptyCachePath).doesNotExist();

        new PGPKeysCache(emptyCachePath, keysServerClient);

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

        assertThatCode(() -> new PGPKeysCache(fileAsCachePath, keysServerClient))
                .isExactlyInstanceOf(IOException.class)
                .hasMessageStartingWith("PGP keys cache path exist but is not a directory:");
    }

    @Test
    public void getKeyFromCache() throws IOException, PGPException {

        PGPKeysCache pgpKeysCache = new PGPKeysCache(cachePath.toFile(), keysServerClient);

        // first call retrieve key from server
        PGPPublicKeyRing keyRing = pgpKeysCache.getKeyRing(0xEFE8086F9E93774EL);

        assertThat(keyRing)
                .hasSize(2)
                .anyMatch(key -> key.getKeyID() == 0xEFE8086F9E93774EL);

        verify(keysServerClient).getUriForGetKey(anyLong());
        verify(keysServerClient).copyKeyToOutputStream(anyLong(), any(OutputStream.class), any(PGPKeysServerClient.OnRetryConsumer.class));
        verifyNoMoreInteractions(keysServerClient);
        clearInvocations(keysServerClient);

        // second from cache
        keyRing = pgpKeysCache.getKeyRing(0xEFE8086F9E93774EL);

        assertThat(keyRing)
                .hasSize(2)
                .anyMatch(key -> key.getKeyID() == 0xEFE8086F9E93774EL);

        verifyNoInteractions(keysServerClient);
    }

    @Test
    public void nonExistingKeyInRingThrowException() throws IOException, PGPException {

        PGPKeysCache pgpKeysCache = new PGPKeysCache(cachePath.toFile(), keysServerClient);

        // first call retrieve key from server
        assertThatCode(() -> pgpKeysCache.getKeyRing(0x1234567890L))
                .isExactlyInstanceOf(PGPException.class)
                .hasMessageStartingWith("Can't find public key 0x0000001234567890 in download file:");
    }
}
