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
package org.simplify4u.plugins.keysmap;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.simplify4u.plugins.TestArtifactBuilder.testArtifact;
import static org.simplify4u.plugins.TestUtils.aKeysMapLocationConfig;

import org.apache.maven.artifact.Artifact;
import org.codehaus.plexus.resource.ResourceManager;
import org.codehaus.plexus.resource.loader.ResourceNotFoundException;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.testng.MockitoTestNGListener;
import org.simplify4u.plugins.pgp.KeyFingerprint;
import org.simplify4u.plugins.pgp.KeyInfo;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

@Listeners(MockitoTestNGListener.class)
public class KeysMapMultiTest {

    @Mock
    private ResourceManager resourceManager;

    @InjectMocks
    private KeysMap keysMap;

    @BeforeMethod
    public void setup() throws ResourceNotFoundException {
        doAnswer(invocation -> getClass().getResourceAsStream(invocation.getArgument(0)))
                .when(resourceManager).getResourceAsInputStream(anyString());
    }

    @Test
    public void loadMultipleKeysMapShouldContainsAllItems() throws ResourceNotFoundException, IOException {

        keysMap.load(aKeysMapLocationConfig("/keysMapMulti1.list"));
        keysMap.load(aKeysMapLocationConfig("/keysMapMulti2.list"));

        assertThat(keysMap.size()).isEqualTo(9);
    }

    @DataProvider
    public static Object[][] artifactWithKeyToTest() {
        return new Object[][]{
                {testArtifact().build(),
                        new KeyFingerprint("0x1111 1111 1111 1111")},

                {testArtifact().build(),
                        new KeyFingerprint("0x1111 1111 2222 2222")},

                {testArtifact().build(),
                        new KeyFingerprint("0x1111 1111 3333 3333")},

                {testArtifact().artifactId("test1").build(),
                        new KeyFingerprint("0x1111 1111 4444 4444")},

                {testArtifact().build(),
                        new KeyFingerprint("0x2222 2222 1111 1111")},

                {testArtifact().build(),
                        new KeyFingerprint("0x2222 2222 2222 2222")},

                {testArtifact().build(),
                        new KeyFingerprint("0x2222 2222 3333 3333")},

                {testArtifact().groupId("test.group2").build(),
                        new KeyFingerprint("0x2222 2222 4444 4444")},

                {testArtifact().artifactId("bad-sig").build(),
                        new KeyFingerprint("0x2222 2222 5555 5555")},

                {testArtifact().groupId("test.group7").artifactId("test7").build(),
                        new KeyFingerprint("0x7777 7777 7777 7777")}
        };
    }

    @Test(dataProvider = "artifactWithKeyToTest")
    public void keyShouldBeValid(Artifact artifact, KeyFingerprint keyFingerprint)
            throws ResourceNotFoundException, IOException {

        KeyInfo key = KeyInfo.builder().fingerprint(keyFingerprint).build();

        keysMap.load(aKeysMapLocationConfig("/keysMapMulti1.list"));
        keysMap.load(aKeysMapLocationConfig("/keysMapMulti2.list"));

        assertThat(keysMap.isValidKey(artifact, key)).isTrue();
    }

    @DataProvider
    public static Object[][] artifactWithNoSig() {
        return new Object[][]{
                {testArtifact().groupId("test.group-no-sig").artifactId("no-sig").build()},
                {testArtifact().groupId("test.group-no-sig").artifactId("no-sig1").build()},
                {testArtifact().groupId("test.group-no-sig").artifactId("no-sig2").build()}
        };
    }


    @Test(dataProvider = "artifactWithNoSig")
    public void noSigShouldBeFound(Artifact artifact) throws ResourceNotFoundException, IOException {
        keysMap.load(aKeysMapLocationConfig("/keysMapMulti1.list"));
        keysMap.load(aKeysMapLocationConfig("/keysMapMulti2.list"));

        assertThat(keysMap.isNoSignature(artifact)).isTrue();
    }

    @Test
    public void badSigShouldBeFound() throws ResourceNotFoundException, IOException {

        keysMap.load(aKeysMapLocationConfig("/keysMapMulti1.list"));
        keysMap.load(aKeysMapLocationConfig("/keysMapMulti2.list"));

        assertThat(keysMap.isBrokenSignature(testArtifact().artifactId("bad-sig").build())).isTrue();
    }
}
