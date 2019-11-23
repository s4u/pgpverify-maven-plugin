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
assert buildLog.text.contains('[INFO] commons-chain:commons-chain:pom:1.2 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.hamcrest:hamcrest-core:jar:1.3 PGP Signature OK')
assert buildLog.text.contains('[INFO] commons-chain:commons-chain:jar:1.2 PGP Signature OK')
assert buildLog.text.contains('[INFO] junit:junit:jar:4.12 PGP Signature OK')
// Matching on incomplete line to avoid testing for exact (snapshot) version of pgpverify-maven-plugin.
assert buildLog.text.contains('[INFO] org.simplify4u.plugins:pgpverify-maven-plugin:maven-plugin:')
assert buildLog.text.contains(' PGP Signature unavailable, consistent with keys map.')
assert buildLog.text.contains('[INFO] org.apache.maven.plugins:maven-install-plugin:maven-plugin:2.4 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.apache.maven.plugins:maven-install-plugin:pom:2.4 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.apache.maven.plugins:maven-deploy-plugin:maven-plugin:2.7 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.apache.maven.plugins:maven-deploy-plugin:pom:2.7 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.apache.maven.plugins:maven-site-plugin:maven-plugin:3.3 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.apache.maven.plugins:maven-site-plugin:pom:3.3 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.apache.maven.plugins:maven-clean-plugin:maven-plugin:2.5 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.apache.maven.plugins:maven-clean-plugin:pom:2.5 PGP Signature OK')

assert buildLog.text.contains('[INFO] BUILD SUCCESS')
