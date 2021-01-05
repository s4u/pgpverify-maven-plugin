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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import io.vavr.CheckedFunction1;
import io.vavr.control.Try;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.conn.routing.HttpRoutePlanner;
import org.apache.http.protocol.HttpContext;

class RoundRobinRouterPlaner implements HttpRoutePlanner {

    private HttpRoute lastRoute;
    private List<InetAddress> errorAddresses = new ArrayList<>();
    private CheckedFunction1<String, InetAddress[]> resolver = InetAddress::getAllByName;

    public RoundRobinRouterPlaner() {
        // default constructor
    }

    @Override
    public HttpRoute determineRoute(HttpHost target, HttpRequest request, HttpContext context) throws HttpException {

        if (lastRoute == null || !lastRoute.getTargetHost().getHostName().equals(target.getHostName())) {
            // resolve IPs
            List<InetAddress> resolvedAddresses = resolve(target.getHostName());

            // filter failed IP
            Optional<InetAddress> address = resolvedAddresses.stream()
                    .filter(a -> !errorAddresses.contains(a))
                    .findFirst();

            if (!address.isPresent()) {
                // all address was baned - try again
                errorAddresses.removeIf(resolvedAddresses::contains);
                address = Optional.of(resolvedAddresses.get(0));
            }

            HttpHost httpHost = new HttpHost(address.get(), target.getHostName(), target.getPort(),
                    target.getSchemeName());
            boolean secure = "https".equalsIgnoreCase(target.getSchemeName());
            lastRoute = new HttpRoute(httpHost, null, secure);
        }

        return lastRoute;
    }

    /**
     * Resolve hostname and return all IP address as list
     *
     * @param hostName host name to resolve
     *
     * @return arrays of IP address
     */
    private List<InetAddress> resolve(String hostName) throws HttpException {

        return Try.of(() -> Arrays.asList(resolver.apply(hostName)))
                .getOrElseThrow(e -> new HttpException("UnknownHostException: " + hostName, e));
    }

    /**
     * Inform that error was occurred on last route.
     *
     * @return last used route
     */
    public HttpRoute lastRouteCauseError() {
        HttpRoute ret = lastRoute;
        if (lastRoute != null) {
            errorAddresses.add(lastRoute.getTargetHost().getAddress());
            lastRoute = null;
        }
        return ret;
    }
}
