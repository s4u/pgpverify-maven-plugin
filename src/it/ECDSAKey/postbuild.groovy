

def buildLog = new File( basedir, 'build.log' )

assert buildLog.text.contains('[INFO] com.github.exabrial:form-binding:jar:1.2.0 PGP Signature OK')
// ECDSA = 19, SHA512 = 10
assert buildLog.text.contains('[DEBUG] signature.KeyAlgorithm: 19 signature.hashAlgorithm: 10')
assert buildLog.text.contains('[INFO] BUILD SUCCESS')
