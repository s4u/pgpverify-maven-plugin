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
def buildLog = new File( basedir, 'build.log' )

assert buildLog.text.contains('[INFO] Key server(s) - fallback list: [{http://wrong.address.example.com}, {https://keyserver.ubuntu.com}]')
assert buildLog.text.contains('[WARNING] {http://wrong.address.example.com} throw exception: UnknownHostException: wrong.address.example.com for: http://wrong.address.example.com/pks/lookup?op=get&options=mr&search=0xEFE8086F9E93774E - fallback try next client')
assert buildLog.text.contains('[INFO] Receive key: https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0xEFE8086F9E93774E')

assert buildLog.text.contains('[WARNING] {http://wrong.address.example.com} throw exception: UnknownHostException: wrong.address.example.com for: http://wrong.address.example.com/pks/lookup?op=get&options=mr&search=0xA6ADFC93EF34893E - fallback try next client')
assert buildLog.text.contains('[INFO] Receive key: https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0xA6ADFC93EF34893E')

assert buildLog.text.contains('[INFO] junit:junit:pom:4.12 PGP Signature OK')
assert buildLog.text.contains('[INFO] junit:junit:jar:4.12 PGP Signature OK')
assert buildLog.text.contains('SubKeyId: 0xD4C89EA4AAF455FD88B22087EFE8086F9E93774E of 0x58E79B6ABC762159DC0B1591164BD2247B936711 UserIds: [Marc Philipp (JUnit Development, 2014) <mail@marcphilipp.de>]')

assert buildLog.text.contains('[INFO] org.hamcrest:hamcrest-core:pom:1.3 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.hamcrest:hamcrest-core:jar:1.3 PGP Signature OK')
assert buildLog.text.contains('KeyId: 0x4DB1A49729B053CAF015CEE9A6ADFC93EF34893E UserIds: [Tom Denley (scarytom) <t.denley@cantab.net>]')

assert buildLog.text.contains('[INFO] BUILD SUCCESS')
