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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import io.vavr.CheckedFunction1;
import io.vavr.control.Try;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.conn.routing.HttpRoute;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

@Listeners(MockitoTestNGListener.class)
public class RoundRobinRouterPlanerTest {

    private static final InetAddress[] EXPECTED_ADDRESSES = Try.of(() -> new InetAddress[]{
            InetAddress.getByName("127.0.0.1"),
            InetAddress.getByName("127.0.0.2"),
            InetAddress.getByName("127.0.0.3"),
    }).get();

    private static final String TEST_HOST = "test.host.example.com";

    @Mock
    private CheckedFunction1<String, InetAddress[]> resolver;

    @InjectMocks
    private RoundRobinRouterPlaner routerPlaner;

    @BeforeMethod
    void setup() throws Throwable {
        when(resolver.apply(anyString())).thenReturn(EXPECTED_ADDRESSES);
    }

    @Test
    public void shouldReturnTheSameAddressForSequentialCall() throws HttpException {

        HttpHost httpHost = new HttpHost(TEST_HOST);

        // first call
        HttpRoute firstRoute = routerPlaner.determineRoute(httpHost, null, null);

        for (int i = 0; i < EXPECTED_ADDRESSES.length; i++) {
            HttpRoute httpRouteNext = routerPlaner.determineRoute(httpHost, null, null);
            assertThat(httpRouteNext.getTargetHost().getAddress())
                    .isEqualTo(firstRoute.getTargetHost().getAddress());
        }
    }

    @Test
    public void shouldReturnNextAddressAfterError() throws UnknownHostException, HttpException {

        HttpHost httpHost = new HttpHost(TEST_HOST);

        List<InetAddress> actual = new ArrayList<>();

        for (int i = 0; i < EXPECTED_ADDRESSES.length; i++) {
            HttpRoute httpRoute = routerPlaner.determineRoute(httpHost, null, null);
            routerPlaner.lastRouteCauseError();
            actual.add(httpRoute.getTargetHost().getAddress());
        }

        assertThat(actual).containsExactlyInAnyOrder(EXPECTED_ADDRESSES);

        // after all failed next should be returned
        HttpRoute httpRoute = routerPlaner.determineRoute(httpHost, null, null);
        assertThat(httpRoute.getTargetHost().getAddress()).isIn((Object[]) EXPECTED_ADDRESSES);
    }
}
