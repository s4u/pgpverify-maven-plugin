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

def buildLog = new File( basedir, 'build.log' ).text

assert buildLog.contains('type:        jar')
assert buildLog.contains('type:        pom')
assert buildLog.contains('version:     1.2')

assert buildLog.contains('PGP signature:')
assert buildLog.contains('keyId:       0xB95BBD3FA43C4492')

assert buildLog.contains('PGP key:')
assert buildLog.contains('fingerprint: 0x6E13156C0EE653F0B984663AB95BBD3FA43C4492')
assert buildLog.contains('key is revoked')
assert buildLog.contains('reason:      Key is superseded')

assert buildLog.contains('[INFO] BUILD SUCCESS')
