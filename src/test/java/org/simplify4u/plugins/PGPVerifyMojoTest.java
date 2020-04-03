package org.simplify4u.plugins;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.simplify4u.plugins.utils.ProxyUtil.makeMavenProxy;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Settings;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * test on methods in the mojo itself
 */
public class PGPVerifyMojoTest {

    /**
     * test that if we set a proxy, we want to ensure that it is the right one from our config
     * @throws Exception unexcpected reflection issues etc.
     */
    @Test
    public void testIfProxyDeterminationWorksUsingIDs() throws Exception {

        List<Proxy> proxies = Arrays.asList(
            makeMavenProxy(null, null, "p1", true),
            makeMavenProxy(null, null, "p2", false));

        PGPVerifyMojo mojo = new PGPVerifyMojo();
        Field settings = PGPVerifyMojo.class.getDeclaredField("settings");
        settings.setAccessible(true);
        Settings mavenSettings = mock(Settings.class);
        settings.set(mojo, mavenSettings);
        Field proxyName = PGPVerifyMojo.class.getDeclaredField("proxyName");
        proxyName.setAccessible(true);

        when(mavenSettings.getProxies()).thenReturn(proxies);

        proxyName.set(mojo, "p2");
        Assert.assertEquals(mojo.getMavenProxy().getId(), "p2");
        proxyName.set(mojo, "p1");
        Assert.assertEquals(mojo.getMavenProxy().getId(), "p1");
        proxyName.set(mojo, "p3");
        Assert.assertNull(mojo.getMavenProxy());
    }

    /**
     * If the proxy is not set, it should take the first active one
     * @throws Exception unexpected reflection issue
     */
    @Test
    public void testIfProxyDeterminationWorksUsinFirstActive() throws Exception {
        List<Proxy> proxies = Arrays.asList(
            makeMavenProxy(null, null, "p1", false),
            makeMavenProxy(null, null, "p2", true));
        PGPVerifyMojo mojo = new PGPVerifyMojo();
        Field settings = PGPVerifyMojo.class.getDeclaredField("settings");
        settings.setAccessible(true);
        Settings mavenSettings = mock(Settings.class);
        settings.set(mojo, mavenSettings);
        Field proxyName = PGPVerifyMojo.class.getDeclaredField("proxyName");
        proxyName.setAccessible(true);

        when(mavenSettings.getProxies()).thenReturn(proxies);

        proxyName.set(mojo, null);
        Assert.assertEquals(mojo.getMavenProxy().getId(), "p2");
    }

}
