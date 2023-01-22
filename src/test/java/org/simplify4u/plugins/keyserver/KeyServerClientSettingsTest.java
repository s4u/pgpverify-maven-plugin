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

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.simplify4u.plugins.utils.ProxyUtil.makeMavenProxy;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Settings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * test on methods in the mojo itself
 */
@ExtendWith(MockitoExtension.class)
class KeyServerClientSettingsTest {

    @Mock
    private MavenSession mavenSession;

    @Mock
    private Settings settings;

    /**
     * test that if we set a proxy, we want to ensure that it is the right one from our config
     *
     */
    @Test
    void testIfProxyDeterminationWorksUsingIDs() {

        List<Proxy> proxies = Arrays.asList(
                makeMavenProxy(null, null, "p1", true),
                makeMavenProxy(null, null, "p2", false));

        when(mavenSession.getSettings()).thenReturn(settings);
        when(settings.getProxies()).thenReturn(proxies);

        Optional<Proxy> p1 = KeyServerClientSettings.builder().mavenSession(mavenSession).proxyName("p1").build().getProxy();
        assertThat(p1).map(Proxy::getId).hasValue("p1");

        Optional<Proxy> p2 = KeyServerClientSettings.builder().mavenSession(mavenSession).proxyName("p2").build().getProxy();
        assertThat(p2).map(Proxy::getId).hasValue("p2");

        Optional<Proxy> p3 = KeyServerClientSettings.builder().mavenSession(mavenSession).proxyName("p3").build().getProxy();

        assertThat(p3).isEmpty();

        verify(settings, times(3)).getProxies();
        verifyNoMoreInteractions(settings);
    }

    /**
     * If the proxy is not set, it should take the first active one
     *
     */
    @Test
    void testIfProxyDeterminationWorksUsinFirstActive() {

        when(mavenSession.getSettings()).thenReturn(settings);
        when(settings.getActiveProxy()).thenReturn(makeMavenProxy("p5"));

        Optional<Proxy> proxy = KeyServerClientSettings.builder().mavenSession(mavenSession).build().getProxy();
        assertThat(proxy).map(Proxy::getId).hasValue("p5");

        verify(settings).getActiveProxy();
        verifyNoMoreInteractions(settings);
    }

}
