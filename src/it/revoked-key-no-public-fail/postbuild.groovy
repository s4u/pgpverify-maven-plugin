/*
 * Copyright 2020 Slawomir Jaranowski
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

assert buildLog.contains('[ERROR] com.amazonaws:aws-java-sdk-sns:pom:1.10.72 PGP key 0x03BD3C33F16AB41B has been revoked and public key is not available')
assert buildLog.contains('[ERROR] com.amazonaws:aws-java-sdk-sns:jar:1.10.72 PGP key 0x03BD3C33F16AB41B has been revoked and public key is not available')
