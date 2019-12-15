/*
 * Copyright 2019 Slawomir Jaranowski
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
package org.simplify4u.plugins;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.conn.routing.HttpRoute;
import org.testng.Assert;
import org.testng.annotations.Test;

public class RoundRobinRouterPlanerIT {

    public static final String TEST_HOST = "hkps.pool.sks-keyservers.net";

    @Test
    public void shouldReturnTheSameAddressForSequentialCall() throws UnknownHostException, HttpException {

        InetAddress[] expected = InetAddress.getAllByName(TEST_HOST);

        RoundRobinRouterPlaner routerPlaner = new RoundRobinRouterPlaner();
        HttpHost httpHost = new HttpHost(TEST_HOST);

        // first call
        HttpRoute firstRoute = routerPlaner.determineRoute(httpHost, null, null);

        for (int i = 0; i < expected.length; i++) {
            HttpRoute httpRouteNext = routerPlaner.determineRoute(httpHost, null, null);
            assertEquals(httpRouteNext.getTargetHost().getAddress(), firstRoute.getTargetHost().getAddress());
        }
    }

    @Test
    public void shouldReturnNextAddressAfterError() throws UnknownHostException, HttpException {
        InetAddress[] expected = InetAddress.getAllByName(TEST_HOST);

        RoundRobinRouterPlaner routerPlaner = new RoundRobinRouterPlaner();
        HttpHost httpHost = new HttpHost(TEST_HOST);

        List<InetAddress> actual = new ArrayList<>();

        for (int i = 0; i < expected.length; i++) {
            HttpRoute httpRoute = routerPlaner.determineRoute(httpHost, null, null);
            routerPlaner.lastRouteCauseError();
            actual.add(httpRoute.getTargetHost().getAddress());
        }

        Assert.assertEqualsNoOrder(actual.toArray(), expected);

        // after all failed next should be returned
        HttpRoute httpRoute = routerPlaner.determineRoute(httpHost, null, null);
        assertTrue(Arrays.asList(expected).contains(httpRoute.getTargetHost().getAddress()));
    }
}
