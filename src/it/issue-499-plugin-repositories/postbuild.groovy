

def buildLog = new File( basedir, 'build.log' )

// only check that plugin was resolved
assert buildLog.text.contains('org.codehaus.groovy:groovy-eclipse-compiler:jar:3.9.0')
assert buildLog.text.contains('org.codehaus.groovy:groovy-eclipse-compiler:pom:3.9.0')
