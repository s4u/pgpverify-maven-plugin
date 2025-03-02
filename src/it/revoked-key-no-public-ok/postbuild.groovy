/*
 * Copyright 2025 Slawomir Jaranowski
 * Portions copyright 2020 Danny van Heumen
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

assert buildLog.contains('[INFO] com.amazonaws:aws-java-sdk-sns:pom:1.10.72 PGP key 0x03BD3C33F16AB41B is revoked and has no public key, consistent with keys map.')
assert buildLog.contains('[INFO] com.amazonaws:aws-java-sdk-sns:jar:1.10.72 PGP key 0x03BD3C33F16AB41B is revoked and has no public key, consistent with keys map.')

assert buildLog.contains('[INFO] net.sourceforge.pmd:pmd:pom:7.7.0 PGP key 0xEBB241A545CB17C87FACB2EBD0BF1D737C9A1C22 is revoked and has no public key, consistent with keys map.')
