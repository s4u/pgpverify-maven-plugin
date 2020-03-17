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

assert buildLog.text.contains('[INFO] commons-chain:commons-chain:jar:1.2 PGP Signature OK')
assert buildLog.text.contains('KeyId: 0xD196A5E3E70732EEB2E5007F1861C322C56014B2')
assert buildLog.text.contains('[INFO] commons-chain:commons-chain:pom:1.2 PGP Signature OK')
assert buildLog.text.contains('KeyId: 0x6E13156C0EE653F0B984663AB95BBD3FA43C4492')

assert buildLog.text.contains('[INFO] BUILD SUCCESS')
