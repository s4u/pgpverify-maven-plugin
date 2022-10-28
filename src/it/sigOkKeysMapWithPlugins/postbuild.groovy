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

// matches('(?ms).*^\\[INFO\\] org.bouncycastle:bcpg-jdk15on:jar:.* PGP Signature OK$.*')

assert buildLog.contains('[INFO] NOTE: maven-surefire-plugin version 3 is present. This version is known to resolve and load dependencies for various unit testing frameworks (called \"providers\") during execution. These dependencies are not validated.')
assert buildLog.contains('[INFO] junit:junit:pom:4.12 PGP Signature OK')
assert buildLog.contains('[INFO] org.hamcrest:hamcrest-core:pom:1.3 PGP Signature OK')
assert buildLog.contains('[INFO] commons-chain:commons-chain:pom:1.2 PGP Signature OK')
assert buildLog.contains('[INFO] org.hamcrest:hamcrest-core:jar:1.3 PGP Signature OK')
assert buildLog.contains('[INFO] commons-chain:commons-chain:jar:1.2 PGP Signature OK')
assert buildLog.contains('[INFO] junit:junit:jar:4.12 PGP Signature OK')
assert buildLog.contains('[INFO] org.apache.maven.plugins:maven-install-plugin:maven-plugin:3.0.0-M1 PGP Signature OK')
assert buildLog.contains('[INFO] org.apache.maven.plugins:maven-install-plugin:pom:3.0.0-M1 PGP Signature OK')
assert buildLog.contains('[INFO] org.apache.maven.plugins:maven-deploy-plugin:maven-plugin:3.0.0-M2 PGP Signature OK')
assert buildLog.contains('[INFO] org.apache.maven.plugins:maven-deploy-plugin:pom:3.0.0-M2 PGP Signature OK')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.apache.maven.plugins:maven-site-plugin:maven-plugin:.* PGP Signature OK$.*')
assert buildLog.matches('(?ms).*^\\[INFO\\] org.apache.maven.plugins:maven-site-plugin:pom:.* PGP Signature OK$.*')
assert buildLog.contains('[INFO] org.apache.maven.plugins:maven-clean-plugin:maven-plugin:3.2.0 PGP Signature OK')
assert buildLog.contains('[INFO] org.apache.maven.plugins:maven-clean-plugin:pom:3.2.0 PGP Signature OK')
assert buildLog.contains('[INFO] org.apache.maven.plugins:maven-pmd-plugin:maven-plugin:3.12.0 PGP Signature OK')
assert buildLog.contains('[INFO] org.apache.maven.plugins:maven-pmd-plugin:pom:3.12.0 PGP Signature OK')
assert buildLog.contains('[INFO] net.sourceforge.pmd:pmd-java:jar:6.15.0 PGP Signature OK')
assert buildLog.contains('[INFO] net.sourceforge.pmd:pmd-java:pom:6.15.0 PGP Signature OK')
assert buildLog.contains('[INFO] net.sourceforge.pmd:pmd-core:jar:6.15.0 PGP Signature OK')
assert buildLog.contains('[INFO] net.sourceforge.pmd:pmd-core:pom:6.15.0 PGP Signature OK')
assert buildLog.contains('[INFO] com.google.errorprone:error_prone_core:jar:2.3.3 PGP Signature OK')
assert buildLog.contains('[INFO] com.google.errorprone:error_prone_core:pom:2.3.3 PGP Signature OK')
assert buildLog.contains('[INFO] com.uber.nullaway:nullaway:jar:0.7.8 PGP Signature OK')
assert buildLog.contains('[INFO] com.uber.nullaway:nullaway:pom:0.7.8 PGP Signature OK')
assert buildLog.contains('[INFO] org.apache.maven.plugins:maven-project-info-reports-plugin:maven-plugin:3.0.0 PGP Signature OK')
assert buildLog.contains('[INFO] org.apache.maven.plugins:maven-project-info-reports-plugin:pom:3.0.0 PGP Signature OK')
assert buildLog.contains('[INFO] BUILD SUCCESS')
