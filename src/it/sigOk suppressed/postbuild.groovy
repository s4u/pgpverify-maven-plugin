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

assertFalse buildLog.contains('[INFO] com.google.auto.value:auto-value-annotations:pom:1.6.3 PGP Signature OK')
assertFalse buildLog.contains('[INFO] com.google.auto.value:auto-value-annotations:jar:1.6.3 PGP Signature OK')
// split key infskip search for special char - this assertion cause problem on windows system
assert !buildLog.contains('KeyId: 0xC7BE5BCC9FEC15518CFDA882B0F3710FA64900E7 UserIds:')
assert !buildLog.contains('amonn McManus <eamonn@mcmanus.net>]')

assert !buildLog.contains('[INFO] junit:junit:pom:4.12 PGP Signature OK')
assert !buildLog.contains('[INFO] junit:junit:jar:4.12 PGP Signature OK')
assert !buildLog.contains('SubKeyId: 0xD4C89EA4AAF455FD88B22087EFE8086F9E93774E of 0x58E79B6ABC762159DC0B1591164BD2247B936711 UserIds: [Marc Philipp (JUnit Development, 2014) <mail@marcphilipp.de>]')

assert !buildLog.contains('[INFO] org.hamcrest:hamcrest-core:pom:1.3 PGP Signature OK')
assert !buildLog.contains('[INFO] org.hamcrest:hamcrest-core:jar:1.3 PGP Signature OK')
assert !buildLog.contains('KeyId: 0x4DB1A49729B053CAF015CEE9A6ADFC93EF34893E UserIds: [Tom Denley (scarytom) <t.denley@cantab.net>]')

assert !buildLog.contains('[INFO] org.apache.xmlgraphics:fop:pom:0.95 PGP Signature OK')
assert !buildLog.contains('[INFO] org.apache.xmlgraphics:fop:jar:0.95 PGP Signature OK')
assert !buildLog.contains('SubKeyId: 0x38D9DE3F3966A706C8C2C5CF8E1E35C66754351B of 0xAB6638CE472A499B3959ADA2F989A2E5C93C5700 UserIds: [Maximilian Berger, Maximilian Berger <max@berger.name>, Maximilian Berger <maxberger@apache.org>]')

assert buildLog.contains('[INFO] BUILD SUCCESS')
