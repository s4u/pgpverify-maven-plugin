KeysMap file format
====================

The format of the file is similar to, but more flexible than, a Java properties file.
The syntax of each line of properties file is:

    groupId:artifactId:packaging:version=pgpKeyFingerprint
    
Where

- `groupId`           - groupId of Maven artifact, this field is required, but can be `*` for match any   
- `artifactId`        - artifactId of Maven artifact - optional
- `packaging`         - packaging of Maven artifact, eg. `pom`, `jar` - optional 
- `version`           - version of Maven artifact, this field supports Maven version range syntax or regular expressions - optional
- `pgpKeyFingerprint` - PGP key fingerprints in hex format which are allowed to sign artifact,
                 multiple keys can be supplied separated by comma  

PGP keys special values
----------------------

`pgpKey` field can contains multiple PGP fingerprints, separated by a comma,
each fingerprint must start with `0x`. Whitespace is allowed in hex fingerprint.

`pgpKey` can also contain special values:

- `*`, `any` - match any key for artifact
- `noSig`    - allow artifact without signature
- `badSig`   - allow artifact with invalid signature
- `noKey`    - allow that key for artifact will not exist on public key servers

The order of items and matching
-------------------------------

The order of items is not important.

In first step items are filtered for matching artifact and then fingerprints or special key value are searched until first is found.

Comments 
--------

Everything from `#` (hash sign) and continue to the end of the line are comment and will be skipped.    

Multiline
---------

If line is ending with ` \ ` (backslash), break of line will be removed and next line will be joined.

Whitespace and comments are allowed after ` \ `.

Version Regular Expressions
---------

When the version field begins with ` ~ ` (tilde), everything following the tilde is a case-insensitive regular
expression matched against artifact version.

When the version field begins with ` !~ ` (not-tilde), everything following the not-tilde is a case-insensitive regular
expression with a negated match against artifact version.

This may be used, for example, to have separate PGP signing keys for continuous integration snapshot builds,
while releases are signed by more protected PGP keys unavailable to the continuous integration platform.

Examples
--------

match any artifact from group with any packaging and version 

    test.groupId = 0x1234567890123456789012345678901234567890
---

match any artifact from group and any subgroups with any packaging and version 

    test.groupId.* = 0x1234567890123456789012345678901234567890  
---

match a specific artifact with any packaging and version

    test.groupId:artifactId = 0x1234567890123456789012345678901234567890  
---

match a specific artifact with packaging and with any version

    test.groupId:artifactId:jar = 0x1234567890123456789012345678901234567890
---

match a specific artifact with packaging and version

    test.groupId:artifactId:jar:1.0.0 = 0x1234567890123456789012345678901234567890
---

match a specific artifact with packaging and version range

    test.groupId:artifactId:jar:[1.0.0,2.0.0) = 0x1234567890123456789012345678901234567890
---

match a specific artifact with the version and any packaging

    test.groupId:artifactId:1.0.0 = 0x1234567890123456789012345678901234567890  
---

match any artifact from group with any packaging and a SNAPSHOT/timestamped version by regular expression

    test.groupId:*:~.*-(SNAPSHOT|\d{8,}\.\d{6}-\d+) = 0x1234567890123456789012345678901234567890
---

match any artifact from group with any packaging and a non-SNAPSHOT/timestamped version by negated regular expression

    test.groupId:*:!~.*-(SNAPSHOT|\d{8,}\.\d{6}-\d+) = 0x1234567890123456789012345678901234567890
---

match a specific artifact with any packaging and a SNAPSHOT/timestamped version by regular expression

    test.groupId:artifactId:~.*-(SNAPSHOT|\d{8,}\.\d{6}-\d+) = 0x1234567890123456789012345678901234567890
---

match a specific artifact with specific packaging and a SNAPSHOT/timestamped version by regular expression

    test.groupId:artifactId:jar:~.*-(SNAPSHOT|\d{8,}\.\d{6}-\d+) = 0x1234567890123456789012345678901234567890
---

match a specific artifact with any version and packaging and many keys
   
    test.groupId:artifactId = 0x1234567890123456789012345678901234567890, 0x1234567890123456789012345678901234567890, \ 
                              0x1234567890123456789012345678901234567890
---

allow bad signature for a specific artifact with version

    test.groupId:artifactId           = 0x1234567890123456789012345678901234567890
    test.groupId:artifactId:pom:1.0.0 = badSig
---

match specific artifact with any packaging and version and allow that signature will not exist

    test.groupId:artifactId = 0x1234567890123456789012345678901234567890, noSig
---

define fingerprints for group and one for specific artifact

    test.groupId            = 0x1111222233334444555566667777888899990000
    test.groupId:artifactId = 0x0000999988887777666655554444333322221111

in this case every artifact from group `test.groupId` can be signed by key `0x1111222233334444555566667777888899990000`.

artifact `test.groupId:artifactId` can be signed by `0x0000999988887777666655554444333322221111`
and also by `0x1111222233334444555566667777888899990000`.

---

comments
   
    # my comments
    test.groupId:artifactId = \               # 
                              0x1234567890123456789012345678901234567890, \ # first key 
                              0x1234567890123456789012345678901234567890, \ # second key
                              0x1234567890123456789012345678901234567890    # end 
---

External resources
------------------
 
- [Maven GAV - naming conventions](https://maven.apache.org/guides/mini/guide-naming-conventions.html)
- [Version range syntax](https://maven.apache.org/enforcer/enforcer-rules/versionRanges.html)
