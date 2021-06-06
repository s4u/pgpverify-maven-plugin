Report file format
==================

`check` goal can generate report with verification result.

Report file is written in `JSON`format, contains arrays of report item.

Example:

```json
[
  {
    "artifact": {
      "groupId": "groupId",
      "artifactId": "artifactId",
      "type": "jar",
      "version": "1.0",
      "classifier": "classifier"
    },
    "key": {
      "fingerprint": "0x12345678901234567890",
      "master": "0x09876543210987654321",
      "uids": [
        "Test uid <uid@example.com>"
      ],
      "version": 4,
      "algorithm": 1,
      "bits": 2048,
      "date": "2020-06-05T11:22:33.444+00:00"
    },
    "keyShowUrl": "https://example.com/key",
    "signature": {
      "hashAlgorithm": 1,
      "keyAlgorithm": 1,
      "keyId": "0x0000000000001234",
      "date": "2020-06-05T11:22:33.444+00:00",
      "version": 4
    },
    "status": "SIGNATURE_VALID"
  },
  {
    "artifact": {
      "groupId": "groupId",
      "artifactId": "artifactId",
      "type": "jar",
      "version": "1.0",
      "classifier": "classifier"
    },
    "key": {
      "fingerprint": "0x12345678901234567890",
      "master": "0x09876543210987654321",
      "uids": [
        "Test uid <uid@example.com>"
      ],
      "version": 4,
      "algorithm": 1,
      "bits": 2048,
      "date": "2020-04-22T10:22:33.444+00:00"
    },
    "keyShowUrl": "https://example.com/key",
    "signature": {
      "hashAlgorithm": 1,
      "keyAlgorithm": 1,
      "keyId": "0x0000000000001234",
      "date": "2020-04-22T10:22:33.444+00:00",
      "version": 4
    },
    "status": "SIGNATURE_ERROR",
    "errorMessage": "io error"
  }
]
```

Item
----

Each item of array has described by:

| item         | description                                   |
| ------------ | --------------------------------------------- |
| artifact     | maven artifact                                |
| key          | key used to sign artifact                     |
| signature    | signature attached to artifact                |
| keyShowUrl   | url address to key server where key was found |
| status       | verification status                           |
| errorMessage | optional error message in case of any problem |


Artifact 
--------

| item       | description               |
| ---------- | ------------------------- |
| groupId    | maven groupId             |
| artifactId | maven artifactId          |
| type       | maven type                |
| version    | maven version             |
| classifier | optional maven classifier |


Key
---

| item        | description                                                               |
| ----------- | ------------------------------------------------------------------------- |
| fingerprint | key fingerprint                                                           |
| master      | master key fingerprint - if present fingerprint is subkey                 | 
| uids        | arrays of key uids                                                        |
| version     | OpenPGP key version                                                       |
| algorithm   | key algorithm - https://datatracker.ietf.org/doc/html/rfc4880#section-9.1 | 
| bits        | key length                                                                |
| date        | key creation date                                                         |

Signature
---------

| item        | description                                                                             |
| ----------- | --------------------------------------------------------------------------------------- |
| hashAlgorithm | signature hash algorithms - https://datatracker.ietf.org/doc/html/rfc4880#section-9.4 |
| keyAlgorithm | key algorithm - https://datatracker.ietf.org/doc/html/rfc4880#section-9.1              |
| keyId | key id/fingerprint from signature                                                             |
| date | signature creation date                                                                        |
| version | OpenPGP signature version                                                                   |

Status
------

Verification status, can be:

- `SIGNATURE_VALID` - artifact contains valid signature
- `SIGNATURE_INVALID` - signature attached to artifact is not valid,
- `SIGNATURE_NOT_RESOLVED` - signature for artifact was not found
- `KEY_NOT_FOUND` - key referenced in signature was not found on available key servers
- `SIGNATURE_ERROR` - signature process error
- `ERROR` - another error during processed 
