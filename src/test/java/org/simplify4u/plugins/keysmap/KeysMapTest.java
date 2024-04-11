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
package org.simplify4u.plugins.keysmap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.simplify4u.plugins.TestArtifactBuilder.testArtifact;
import static org.simplify4u.plugins.TestUtils.aKeyInfo;
import static org.simplify4u.plugins.TestUtils.aKeysMapLocationConfig;

import org.apache.maven.artifact.Artifact;
import org.codehaus.plexus.resource.ResourceManager;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.junit.jupiter.api.Test;

/**
 * @author Slawomir Jaranowski.
 */
@ExtendWith(MockitoExtension.class)
class KeysMapTest {

    @Mock
    private ResourceManager resourceManager;

    @Mock(name = "org.simplify4u.plugins.keysmap.KeysMap")
    private Logger loggerKeysMap;

    @Mock(name = "org.simplify4u.plugins.keysmap.KeyItems")
    private Logger loggerKeyItems;

    @InjectMocks
    private KeysMap keysMap;

    @Test
    void isComponentSet() {
        assertThat(keysMap).isNotNull();
    }

    @Test
    void nullLocationTest() throws Exception {

        assertThatThrownBy(() -> keysMap.load(null))
                .isExactlyInstanceOf(NullPointerException.class);

        verifyNoInteractions(resourceManager);
        assertThat(keysMap.isValidKey(testArtifact().build(), null)).isTrue();
    }

    @Test
    void emptyLocationTest() throws Exception {
        keysMap.load(aKeysMapLocationConfig(""));

        verifyNoInteractions(resourceManager);
        assertThat(keysMap.isValidKey(testArtifact().build(), null)).isTrue();
    }

    @Test
    void validKeyFromMap() throws Exception {

        doAnswer(invocation -> getClass().getResourceAsStream(invocation.getArgument(0)))
                .when(resourceManager).getResourceAsInputStream(anyString());

        keysMap.load(aKeysMapLocationConfig("/keysMap.list"));

        verify(resourceManager).getResourceAsInputStream(anyString());

        assertThat(
                keysMap.isValidKey(
                        testArtifact().groupId("junit").artifactId("junit").version("4.12").build(),
                        aKeyInfo("0x123456789abcdef0"))
        ).isTrue();

        assertThat(
                keysMap.isValidKey(
                        testArtifact().groupId("junit").artifactId("junit").version("4.12").build(),
                        aKeyInfo("0x123456789abcdeff"))
        ).isTrue();

        assertThat(
                keysMap.isValidKey(
                        testArtifact().groupId("testlong").artifactId("fingerprint").version("x.x.x").build(),
                        aKeyInfo("0x123456789abcdef0"))
        ).isTrue();

        assertThat(
                keysMap.isValidKey(
                        testArtifact().groupId("test.test").artifactId("test").version("1.2.3").build(),
                        aKeyInfo("0x123456789abcdef0"))
        ).isTrue();

        assertThat(
                keysMap.isValidKey(
                        testArtifact().groupId("test").artifactId("test").version("1.0.0").build(),
                        aKeyInfo("0x123456789abcdef0"))
        ).isTrue();

        assertThat(
                keysMap.isValidKey(
                        testArtifact().groupId("test2").artifactId("test-package").version("1.0.0").build(),
                        aKeyInfo("0xA6ADFC93EF34893E"))
        ).isTrue();

        assertThat(
                keysMap.isValidKey(
                        testArtifact().groupId("test2").artifactId("test-package").version("1.0.0").build(),
                        aKeyInfo("0xA6ADFC93EF34893F"))
        ).isTrue();

        assertThat(
                keysMap.isWithKey(testArtifact().groupId("test2").artifactId("test-package").version("1.0.0").build())
        ).isTrue();

        assertThat(
                keysMap.isWithKey(testArtifact().groupId("noSig").artifactId("test").version("1").build())
        ).isFalse();

        assertThat(
                keysMap.isWithKey(testArtifact().groupId("noSig").artifactId("non-existent").version("9999").build())
        ).isFalse();
    }

    @Test
    void invalidKeyFromMap() throws Exception {
        doAnswer(invocation -> getClass().getResourceAsStream(invocation.getArgument(0)))
                .when(resourceManager).getResourceAsInputStream(anyString());

        keysMap.load(aKeysMapLocationConfig("/keysMap.list"));

        verify(resourceManager).getResourceAsInputStream(anyString());

        assertThat(
                keysMap.isValidKey(
                        testArtifact().groupId("junit").artifactId("junit").version("4.11").build(),
                        aKeyInfo("0x123456789abcdef0"))
        ).isFalse();
    }

    @Test
    void specialValueNoSig() throws Exception {
        doAnswer(invocation -> getClass().getResourceAsStream(invocation.getArgument(0)))
                .when(resourceManager).getResourceAsInputStream(anyString());

        keysMap.load(aKeysMapLocationConfig("/keysMap.list"));

        verify(resourceManager).getResourceAsInputStream(anyString());

        assertThat(
                keysMap.isNoSignature(testArtifact().groupId("noSig").artifactId("test").build())
        ).isTrue();

        assertThat(
                keysMap.isNoSignature(testArtifact().groupId("noSig").artifactId("test2").build())
        ).isTrue();

        assertThat(
                keysMap.isNoSignature(testArtifact().groupId("noSig").artifactId("test3").build())
        ).isTrue();

        assertThat(
                keysMap.isValidKey(
                        testArtifact().groupId("noSig").artifactId("test3").build(),
                        aKeyInfo("0x123456789ABCDEF0"))
        ).isTrue();

    }

    @Test
    void specialValueBadSig() throws Exception {
        doAnswer(invocation -> getClass().getResourceAsStream(invocation.getArgument(0)))
                .when(resourceManager).getResourceAsInputStream(anyString());

        keysMap.load(aKeysMapLocationConfig("/keysMap.list"));

        verify(resourceManager).getResourceAsInputStream(anyString());

        assertThat(
                keysMap.isBrokenSignature(testArtifact().groupId("badSig").build())
        ).isTrue();
    }

    @Test
    void specialValueNoKey() throws Exception {
        doAnswer(invocation -> getClass().getResourceAsStream(invocation.getArgument(0)))
                .when(resourceManager).getResourceAsInputStream(anyString());

        keysMap.load(aKeysMapLocationConfig("/keysMap.list"));

        verify(resourceManager).getResourceAsInputStream(anyString());

        assertThat(
                keysMap.isKeyMissing(testArtifact().groupId("noKey").build())
        ).isTrue();
    }

    @Test
    void shortKeyShouldThrownException() throws Exception {
        doAnswer(invocation -> getClass().getResourceAsStream(invocation.getArgument(0)))
                .when(resourceManager).getResourceAsInputStream(anyString());

        KeysMapLocationConfig keysMapLocationConfig = aKeysMapLocationConfig("/keyMap-keyToShort.list");
        assertThatCode(() -> keysMap.load(keysMapLocationConfig))
                .isExactlyInstanceOf(IllegalArgumentException.class)
                .hasMessage("Key length for = 0x10 is 8 bits, should be between 64 and 160 bits");
    }

    @Test
    void properLogShouldBeGeneratedForProcessingItems() throws Exception {
        doAnswer(invocation -> getClass().getResourceAsStream(invocation.getArgument(0)))
                .when(resourceManager).getResourceAsInputStream(anyString());

        keysMap.load(aKeysMapLocationConfig("/keysMap.list"));

        assertThat(keysMap.size()).isEqualTo(11);

        verify(loggerKeysMap)
                .debug(eq("Existing artifact pattern: {} - only update key items in {}"), anyString(),
                        any(KeysMapContext.class));
        verifyNoMoreInteractions(loggerKeysMap);

        verify(loggerKeyItems, times(3))
                .warn(eq("Duplicate key item: {} in: {}"), any(KeyItem.class), any(KeysMapContext.class));
        verify(loggerKeyItems)
                .warn(eq("Empty value for key is deprecated - please provide some value - now assume as noSig in: {}"),
                        any(KeysMapContext.class));
        verifyNoMoreInteractions(loggerKeyItems);
    }

    @Test
    void onlyIncludedItemsFromMapByValue() throws Exception {
        doAnswer(invocation -> getClass().getResourceAsStream(invocation.getArgument(0)))
                .when(resourceManager).getResourceAsInputStream(anyString());

        KeysMapLocationConfig config = aKeysMapLocationConfig("/keysMap.list");
        KeysMapLocationConfig.Filter filter = new KeysMapLocationConfig.Filter();
        filter.setValue("noSig");
        config.addInclude(filter);

        keysMap.load(config);

        assertThat(keysMap.size()).isEqualTo(4);

        assertThat(keysMap.isNoSignature(testArtifact().groupId("noSig").artifactId("test3").build())).isTrue();
        assertThat(keysMap.isKeyMissing(testArtifact().groupId("noKey").build())).isFalse();
    }

    @Test
    void onlyIncludedItemsFromMapByPattern() throws Exception {
        doAnswer(invocation -> getClass().getResourceAsStream(invocation.getArgument(0)))
                .when(resourceManager).getResourceAsInputStream(anyString());

        KeysMapLocationConfig config = aKeysMapLocationConfig("/keysMap.list");
        KeysMapLocationConfig.Filter filter = new KeysMapLocationConfig.Filter();
        filter.setPattern(".*test2");
        config.addInclude(filter);

        keysMap.load(config);

        assertThat(keysMap.size()).isEqualTo(2);

        assertThat(keysMap.isNoSignature(testArtifact().groupId("noSig").artifactId("test2").build())).isTrue();
        assertThat(
                keysMap.isValidKey(
                        testArtifact().groupId("test2").build(),
                        aKeyInfo("0xA6ADFC93EF34893E"))
        ).isTrue();
    }

    @Test
    void excludeItemsFromMap() throws Exception {
        doAnswer(invocation -> getClass().getResourceAsStream(invocation.getArgument(0)))
                .when(resourceManager).getResourceAsInputStream(anyString());

        KeysMapLocationConfig config = aKeysMapLocationConfig("/keysMap.list");
        KeysMapLocationConfig.Filter filter = new KeysMapLocationConfig.Filter();
        filter.setPattern(".*:test2");
        filter.setValue("noSig");
        config.addExclude(filter);

        keysMap.load(config);

        assertThat(keysMap.size()).isEqualTo(10);

        assertThat(keysMap.isNoSignature(testArtifact().groupId("noSig").artifactId("test2").build())).isFalse();
        assertThat(keysMap.isKeyMissing(testArtifact().groupId("noKey").build())).isTrue();
    }

    @Test
    void baseVersionFromArtifactShouldBeUsed() throws Exception {
        doAnswer(invocation -> getClass().getResourceAsStream(invocation.getArgument(0)))
                .when(resourceManager).getResourceAsInputStream(anyString());

        keysMap.load(aKeysMapLocationConfig("/keysMap.list"));

        Artifact snapshot = testArtifact()
                .groupId("noSig")
                .artifactId("test-snapshot")
                .version("1.20.1-R0.1-20240410.215944-178")
                .build();

        assertThat(snapshot.isSnapshot()).isTrue();
        assertThat(snapshot.getBaseVersion()).isEqualTo("1.20.1-R0.1-SNAPSHOT");

        assertThat(keysMap.isNoSignature(snapshot)).isTrue();
    }

}
