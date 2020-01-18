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

assert buildLog.text.contains('[INFO] junit:junit:jar:4.12 PGP Signature OK')
assert buildLog.text.contains('[INFO] junit:junit:pom:4.12 PGP Signature OK')
assert buildLog.text.contains('KeyId: 0xD4C89EA4AAF455FD88B22087EFE8086F9E93774E')

assert buildLog.text.contains('[INFO] org.hamcrest:hamcrest-core:jar:1.3 PGP Signature OK')
assert buildLog.text.contains('[INFO] org.hamcrest:hamcrest-core:pom:1.3 PGP Signature OK')
assert buildLog.text.contains('KeyId: 0x4DB1A49729B053CAF015CEE9A6ADFC93EF34893E')

assert buildLog.text.contains('[INFO] commons-chain:commons-chain:jar:1.2 PGP Signature OK')
assert buildLog.text.contains('KeyId: 0xD196A5E3E70732EEB2E5007F1861C322C56014B2')
assert buildLog.text.contains('[INFO] commons-chain:commons-chain:pom:1.2 PGP Signature OK')
assert buildLog.text.contains('KeyId: 0x6E13156C0EE653F0B984663AB95BBD3FA43C4492')

assert buildLog.text.contains('ognl:ognl:jar:3.1.12 PGP Signature OK')
assert buildLog.text.contains('ognl:ognl:pom:3.1.12 PGP Signature OK')
assert buildLog.text.contains('KeyId: 0x8926173648953916A0A4F290F721C545D0CAA2E3')

assert buildLog.text.contains('org.javassist:javassist:jar:3.20.0-GA PGP Signature OK')
assert buildLog.text.contains('org.javassist:javassist:pom:3.20.0-GA PGP Signature OK')
assert buildLog.text.contains('KeyId: 0x666A4692CE11B7B3F4EB7B3410066A9707090CF9')

assert buildLog.text.contains('[INFO] BUILD SUCCESS')
