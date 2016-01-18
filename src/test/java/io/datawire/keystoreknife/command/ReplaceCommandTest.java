/*
 * Copyright 2016 Datawire. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.datawire.keystoreknife.command;


import io.datawire.util.test.Fixtures;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.*;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

public class ReplaceCommandTest {

  private final Fixtures fixtures = new Fixtures();

  private ArgumentParser argumentParser;
  private Subparsers subparsers;

  @Before
  public void before() {
    argumentParser = ArgumentParsers.newArgumentParser("knife");
    subparsers = argumentParser.addSubparsers();
  }

  @Test
  public void configure_Subparser_ConfiguresSubparserAsExpected() throws ArgumentParserException {
    ReplaceCommand command = new ReplaceCommand();

    Subparser commandParser = subparsers.addParser(command.getName());
    command.configure(commandParser);

    String keystorePath = fixtures.getFixtureFilePath("not_a_real_keystore.jceks");
    String[] args = new String[] {keystorePath, "KEYSTORE_PASSWORD_FOO", "ALIAS_FOO", "PASSWORD_FOO", "NEW_SECRET_FOO"};

    Namespace ns = commandParser.parseArgs(args);
    assertThat((File) ns.get("keystore")).isFile();
    assertThat(ns.getString("keystore_password")).isEqualTo("KEYSTORE_PASSWORD_FOO");
    assertThat(ns.getString("alias")).isEqualTo("ALIAS_FOO");
    assertThat(ns.getString("password")).isEqualTo("PASSWORD_FOO");
    assertThat(ns.getString("new_secret")).isEqualTo("NEW_SECRET_FOO");

    String unreadableFile = String.format("/tmp/%s.jks", UUID.randomUUID().toString());
    try {
      String[] unreadableKeystoreArgs = new String[args.length];
      System.arraycopy(args, 0, unreadableKeystoreArgs, 0, args.length);
      unreadableKeystoreArgs[0] = unreadableFile;

      commandParser.parseArgs(unreadableKeystoreArgs);
      failBecauseExceptionWasNotThrown(ArgumentParserException.class);
    } catch (ArgumentParserException ex) {
      assertThat(ex).hasMessage(
          String.format("argument keystore: Insufficient permissions to read file: '%s'", unreadableFile));
    }
  }
}
