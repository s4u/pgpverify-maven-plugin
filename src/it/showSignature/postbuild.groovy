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
assert buildLog.contains('version:     4.12')

assert buildLog.contains('PGP signature:')
assert buildLog.contains('keyId:       0xEFE8086F9E93774E')

assert buildLog.contains('PGP key:')
assert buildLog.contains('fingerprint: 0xD4C89EA4AAF455FD88B22087EFE8086F9E93774E')
assert buildLog.contains('master key:  0x58E79B6ABC762159DC0B1591164BD2247B936711')

assert buildLog.contains('[INFO] BUILD SUCCESS')
