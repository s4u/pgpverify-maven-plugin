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


assert buildLog.contains('[ERROR] PGP key https://hkps.pool.sks-keyservers.net/pks/lookup?op=vindex&fingerprint=on&search=0x9F1A263E15FD0AC9 not found on keyserver for artifact nl.dannyvanheumen:helloworld:jar:1.0')
assert buildLog.contains('[ERROR] PGP key https://hkps.pool.sks-keyservers.net/pks/lookup?op=vindex&fingerprint=on&search=0x9F1A263E15FD0AC9 not found on keyserver for artifact nl.dannyvanheumen:helloworld:pom:1.0')
assert buildLog.contains('[INFO] BUILD FAILURE')
