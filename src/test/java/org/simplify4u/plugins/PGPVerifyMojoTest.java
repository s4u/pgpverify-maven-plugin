package org.simplify4u.plugins;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;

import static org.mockito.Mockito.when;
import static org.simplify4u.plugins.utils.ProxyUtil.makeMavenProxy;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Settings;
import org.assertj.core.api.Assertions;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

/**
 * test on methods in the mojo itself
 */
@Listeners(MockitoTestNGListener.class)
public class PGPVerifyMojoTest {

    @Mock
    private MavenSession session;

    @Mock
    private Settings settings;

    @InjectMocks
    private PGPVerifyMojo mojo;

    /**
     * test that if we set a proxy, we want to ensure that it is the right one from our config
     *
     * @throws Exception unexcpected reflection issues etc.
     */
    @Test
    public void testIfProxyDeterminationWorksUsingIDs() throws Exception {

        List<Proxy> proxies = Arrays.asList(
                makeMavenProxy(null, null, "p1", true),
                makeMavenProxy(null, null, "p2", false));

        Field proxyName = PGPVerifyMojo.class.getDeclaredField("proxyName");
        proxyName.setAccessible(true);

        when(session.getSettings()).thenReturn(settings);
        when(settings.getProxies()).thenReturn(proxies);

        proxyName.set(mojo, "p2");
        Assertions.assertThat(mojo.getMavenProxy().getId()).isEqualTo("p2");

        proxyName.set(mojo, "p1");
        Assertions.assertThat(mojo.getMavenProxy().getId()).isEqualTo("p1");

        proxyName.set(mojo, "p3");
        Assertions.assertThat(mojo.getMavenProxy()).isNull();
    }

    /**
     * If the proxy is not set, it should take the first active one
     *
     * @throws Exception unexpected reflection issue
     */
    @Test
    public void testIfProxyDeterminationWorksUsinFirstActive() throws Exception {
        List<Proxy> proxies = Arrays.asList(
                makeMavenProxy(null, null, "p1", false),
                makeMavenProxy(null, null, "p2", true));

        Field proxyName = PGPVerifyMojo.class.getDeclaredField("proxyName");
        proxyName.setAccessible(true);

        when(session.getSettings()).thenReturn(settings);
        when(settings.getProxies()).thenReturn(proxies);

        proxyName.set(mojo, null);
        Assert.assertEquals(mojo.getMavenProxy().getId(), "p2");
    }

}
