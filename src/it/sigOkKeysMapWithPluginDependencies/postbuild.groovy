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
def buildLog = new File( basedir, 'build.log' )

assert buildLog.text.contains('[INFO] junit:junit:pom:4.12 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.hamcrest:hamcrest-core:pom:1.3 PGP Signature OK')
assert buildLog.text.contains('[INFO] commons-chain:commons-chain:jar:1.1 PGP Signature unavailable, consistent with keys map.')
assert buildLog.text.contains('[INFO] org.hamcrest:hamcrest-core:jar:1.3 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.slf4j:slf4j-api:jar:1.7.5 PGP Signature OK')
assert buildLog.text.contains('[INFO] io.vavr:vavr-match:jar:0.10.2 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.apache.maven.plugins:maven-site-plugin:pom:3.9.0 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.apache.maven.plugins:maven-compiler-plugin:pom:3.8.1 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.codehaus.plexus:plexus-component-annotations:jar:1.7.1 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.codehaus.plexus:plexus-interpolation:jar:1.14 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.apache.maven:maven-aether-provider:jar:3.0 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.apache.maven.doxia:doxia-site-renderer:jar:1.9 PGP Signature OK')
assert buildLog.text.contains('[INFO] commons-digester:commons-digester:jar:1.8 PGP Signature unavailable, consistent with keys map.')
assert buildLog.text.contains('[INFO] org.apache.velocity:velocity-tools:jar:2.0 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.codehaus.plexus:plexus-io:jar:3.2.0 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.iq80.snappy:snappy:jar:0.4 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.apache.maven:maven-compat:jar:3.0 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.apache.maven.shared:maven-dependency-tree:jar:3.0.1 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.sonatype.plexus:plexus-sec-dispatcher:jar:1.4 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.codehaus.mojo:animal-sniffer-annotations:jar:1.17 PGP Signature OK')
assert buildLog.text.contains('[INFO] com.google.inject:guice:jar:no_aop:4.2.3 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.bouncycastle:bcpg-jdk15on:jar:1.65 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.apache.httpcomponents:httpcore:jar:4.4.13 PGP Signature OK')
assert buildLog.text.contains('[INFO] com.vladsch.flexmark:flexmark-all:jar:0.42.14 PGP Signature OK')
assert buildLog.text.contains('[INFO] commons-validator:commons-validator:jar:1.6 PGP Signature OK')
// Matching on incomplete line to avoid testing for exact (snapshot) version of pgpverify-maven-plugin.
assert buildLog.text.contains('[INFO] org.simplify4u.plugins:pgpverify-maven-plugin:')
assert buildLog.text.contains(' PGP Signature unavailable, consistent with keys map.')
assert buildLog.text.contains('[INFO] BUILD SUCCESS')
