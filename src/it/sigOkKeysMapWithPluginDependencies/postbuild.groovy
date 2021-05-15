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
def buildLog = new File( basedir, 'build.log' ).text

assert buildLog.matches('(?ms).*^\\[INFO\\] junit:junit:pom:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.hamcrest:hamcrest-core:pom:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] commons-chain:commons-chain:jar:.* PGP Signature unavailable, consistent with keys map.$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.hamcrest:hamcrest-core:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.slf4j:slf4j-api:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] io.vavr:vavr-match:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.apache.maven.plugins:maven-site-plugin:pom:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.apache.maven.plugins:maven-compiler-plugin:pom:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.codehaus.plexus:plexus-component-annotations:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.codehaus.plexus:plexus-interpolation:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.apache.maven:maven-aether-provider:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.apache.maven.doxia:doxia-site-renderer:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] commons-digester:commons-digester:jar:.* PGP Signature unavailable, consistent with keys map.$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.apache.velocity:velocity-tools:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.codehaus.plexus:plexus-io:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.iq80.snappy:snappy:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.apache.maven:maven-compat:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.apache.maven.shared:maven-dependency-tree:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.sonatype.plexus:plexus-sec-dispatcher:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.codehaus.mojo:animal-sniffer-annotations:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.bouncycastle:bcpg-jdk15on:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.apache.httpcomponents:httpcore:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] com.vladsch.flexmark:flexmark-all:jar:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] commons-validator:commons-validator:jar:.* PGP Signature OK$.*')
assert buildLog.contains('[INFO] BUILD SUCCESS')
