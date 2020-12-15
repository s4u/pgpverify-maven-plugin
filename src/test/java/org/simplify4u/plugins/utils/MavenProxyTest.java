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
package org.simplify4u.plugins.utils;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.simplify4u.plugins.utils.ProxyUtil.makeMavenProxy;

import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Settings;
import org.assertj.core.api.Condition;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

/**
 * test on methods in the mojo itself
 */
@Listeners(MockitoTestNGListener.class)
public class MavenProxyTest {

    @Mock
    private Settings settings;

    @InjectMocks
    private MavenProxy mavenProxy;

    /**
     * test that if we set a proxy, we want to ensure that it is the right one from our config
     *
     */
    @Test
    public void testIfProxyDeterminationWorksUsingIDs() {

        List<Proxy> proxies = Arrays.asList(
                makeMavenProxy(null, null, "p1", true),
                makeMavenProxy(null, null, "p2", false));

        when(settings.getProxies()).thenReturn(proxies);

        assertThat(mavenProxy.getProxyByName("p2").getId()).isEqualTo("p2");

        assertThat(mavenProxy.getProxyByName("p1").getId()).isEqualTo("p1");

        assertThat(mavenProxy.getProxyByName("p3")).isNull();

        verify(settings, times(3)).getProxies();
        verifyNoMoreInteractions(settings);
    }

    /**
     * If the proxy is not set, it should take the first active one
     *
     */
    @Test
    public void testIfProxyDeterminationWorksUsinFirstActive() {

        when(settings.getActiveProxy()).thenReturn(makeMavenProxy("p5"));

        assertThat(mavenProxy.getProxyByName(null))
                .isNotNull()
                .is(new Condition<>(p -> "p5".equals(p.getId()), ""));

        verify(settings).getActiveProxy();
        verifyNoMoreInteractions(settings);
    }

}
