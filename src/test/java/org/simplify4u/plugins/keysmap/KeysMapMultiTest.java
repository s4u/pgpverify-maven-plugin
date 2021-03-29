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
import static org.simplify4u.plugins.TestUtils.getPGPgpPublicKey;

import org.apache.maven.artifact.Artifact;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.codehaus.plexus.resource.ResourceManager;
import org.codehaus.plexus.resource.loader.ResourceNotFoundException;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.testng.MockitoTestNGListener;
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
                        getPGPgpPublicKey(0x1111_1111_1111_1111L)},

                {testArtifact().build(),
                        getPGPgpPublicKey(0x1111_1111_2222_2222L)},

                {testArtifact().build(),
                        getPGPgpPublicKey(0x1111_1111_3333_3333L)},

                {testArtifact().artifactId("test1").build(),
                        getPGPgpPublicKey(0x1111_1111_4444_4444L)},

                {testArtifact().build(),
                        getPGPgpPublicKey(0x2222_2222_1111_1111L)},

                {testArtifact().build(),
                        getPGPgpPublicKey(0x2222_2222_2222_2222L)},

                {testArtifact().build(),
                        getPGPgpPublicKey(0x2222_2222_3333_3333L)},

                {testArtifact().groupId("test.group2").build(),
                        getPGPgpPublicKey(0x2222_2222_4444_4444L)},

                {testArtifact().artifactId("bad-sig").build(),
                        getPGPgpPublicKey(0x2222_2222_5555_5555L)},

                {testArtifact().groupId("test.group7").artifactId("test7").build(),
                        getPGPgpPublicKey(0x7777_7777_7777_7777L)}
        };
    }

    @Test(dataProvider = "artifactWithKeyToTest")
    public void keyShouldBeValid(Artifact artifact, PGPPublicKey key) throws ResourceNotFoundException, IOException {

        keysMap.load(aKeysMapLocationConfig("/keysMapMulti1.list"));
        keysMap.load(aKeysMapLocationConfig("/keysMapMulti2.list"));

        assertThat(keysMap.isValidKey(artifact, key, null)).isTrue();
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
