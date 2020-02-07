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

assert buildLog.text.contains('[INFO] com.google.auto.value:auto-value-annotations:pom:1.6.3 PGP Signature OK')
assert buildLog.text.contains('[INFO] com.google.auto.value:auto-value-annotations:jar:1.6.3 PGP Signature OK')
assert buildLog.text.contains('KeyId: 0xC7BE5BCC9FEC15518CFDA882B0F3710FA64900E7 UserIds: [�amonn McManus <eamonn@mcmanus.net>]')

assert buildLog.text.contains('[INFO] junit:junit:pom:4.12 PGP Signature OK')
assert buildLog.text.contains('[INFO] junit:junit:jar:4.12 PGP Signature OK')
assert buildLog.text.contains('SubKeyId: 0xEFE8086F9E93774E of 0x58E79B6ABC762159DC0B1591164BD2247B936711 UserIds: [Marc Philipp (JUnit Development, 2014) <mail@marcphilipp.de>]')

assert buildLog.text.contains('[INFO] org.hamcrest:hamcrest-core:pom:1.3 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.hamcrest:hamcrest-core:jar:1.3 PGP Signature OK')
assert buildLog.text.contains('KeyId: 0x4DB1A49729B053CAF015CEE9A6ADFC93EF34893E UserIds: [Tom Denley (scarytom) <t.denley@cantab.net>]')

assert buildLog.text.contains('[INFO] BUILD SUCCESS')
