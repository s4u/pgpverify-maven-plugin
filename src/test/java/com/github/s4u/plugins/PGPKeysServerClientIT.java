/*
 * Copyright 2016 Slawomir Jaranowski
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
package com.github.s4u.plugins;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

import com.google.common.io.ByteStreams;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class PGPKeysServerClientIT {

    private static final long TEST_KEYID = 0xF8484389379ACEACL;

    @DataProvider(name = "urlToTest")
    Object[][] urlToTest() {
        return new Object[][]{
                {"hkp://pool.sks-keyservers.net"},
                {"hkp://p80.pool.sks-keyservers.net:80"},
                {"http://p80.pool.sks-keyservers.net"},
                {"hkps://pgp.mit.edu/"},
                {"hkps://hkps.pool.sks-keyservers.net"}
        };
    }

    @Test(dataProvider = "urlToTest")
    public void testClient(String keyServerUrl) throws Exception {

        File tempFile = File.createTempFile("PGPClientTest", null);
        tempFile.deleteOnExit();

        PGPKeysServerClient pgpKeysServerClient = PGPKeysServerClient.getInstance(keyServerUrl);

        try (InputStream inputStream = pgpKeysServerClient.getInputStreamForKey(TEST_KEYID);
             FileOutputStream outputStream = new FileOutputStream(tempFile)) {
            ByteStreams.copy(inputStream, outputStream);
        }

        Assert.assertTrue(tempFile.length() > 0, "Download key is empty");
    }
}
