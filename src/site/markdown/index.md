# Verify PGP signatures plugin

This plugin allow you to automatically verify PGP signature of all project dependency.

You can try it by running in your project:

    mvn com.github.s4u.plugins:pgpverify-maven-plugin:check

If you want check your dependency on each build, please add to your project:

    <project>
      ...
      <build>
        <!-- To define the plugin version in your parent POM -->
        <pluginManagement>
          <plugins>
            <plugin>
              <groupId>com.github.s4u.plugins</groupId>
              <artifactId>pgpverify-maven-plugin</artifactId>
              <version>1.0.0</version>
            </plugin>
            ...
          </plugins>
        </pluginManagement>

        <!-- To use the plugin goals in your POM or parent POM -->
        <plugins>
          <plugin>
            <groupId>com.github.s4u.plugins</groupId>
            <artifactId>pgpverify-maven-plugin</artifactId>
            <executions>
                <execution>
                    <goals>
                        <goal>check</goal>
                    </goals>
                </execution>
             </executions>
          </plugin>
          ...
        </plugins>
      </build>
      ...
    </project>
