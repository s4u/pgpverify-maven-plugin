/*
 * Copyright 2021 Slawomir Jaranowski
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


assert buildLog.contains('[INFO] junit:junit:jar:4.12 PGP Signature OK')
assert buildLog.contains('[INFO] junit:junit:pom:4.12 PGP Signature OK')

assert buildLog.contains('[INFO] commons-chain:commons-chain:jar:1.2 PGP Signature OK')
assert buildLog.contains('[INFO] commons-chain:commons-chain:pom:1.2 PGP Signature OK')

assert buildLog.contains('[ERROR] Not allowed artifact org.hamcrest:hamcrest-core:jar:1.3 and keyID:')
assert buildLog.contains('[ERROR] Not allowed artifact org.hamcrest:hamcrest-core:pom:1.3 and keyID:')

assert buildLog.contains('[INFO] commons-beanutils:commons-beanutils:jar:1.7.0 PGP Signature unavailable, consistent with keys map.')
assert buildLog.contains('[INFO] commons-logging:commons-logging:jar:1.0.3 PGP Signature unavailable, consistent with keys map.')

assert buildLog.contains('[INFO] BUILD FAILURE')
