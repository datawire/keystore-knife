/*
 * Copyright 2015 Datawire. All rights reserved.
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


import io.datawire.keystoreknife.KeyStoreKnife;
import io.datawire.app.Initializer;
import io.datawire.app.command.Command;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.Namespace;
import net.sourceforge.argparse4j.inf.Subparser;

import javax.crypto.SecretKey;
import java.io.File;

public class ReplaceCommand extends Command {

  public ReplaceCommand() {
    super("replace-secret", "Replaces an existing secret key with a different one");
  }

  @Override
  public void configure(Subparser subparser) {
    subparser.addArgument("keystore")
        .help("the keystore to open and modify")
        .type(Arguments.fileType().verifyCanRead());

    subparser.addArgument("--keystore-type").setDefault("JCEKS");
    subparser.addArgument("--out");

    subparser.addArgument("keystore_password").help("the keystore password");
    subparser.addArgument("alias").help("the alias of the secret being replaced");
    subparser.addArgument("password").help("the password protecting the secret");
    subparser.addArgument("new_secret").help("the new secret that should replace the old one");
  }

  @Override
  public void run(Initializer<?> initializer, Namespace namespace) throws Exception {
    KeyStoreKnife knife = KeyStoreKnife.create(
        namespace.get("keystore"), namespace.getString("keystore_type"), namespace.getString("keystore_password"));

    final String keyStorePassword = namespace.getString("keystore_password");
    final String keyAlias = namespace.getString("alias");
    final String keyPassword = namespace.getString("password");

//    byte[] newSecret = namespace.getString("new_secret").getBytes(StandardCharsets.UTF_8);

    SecretKey currentKey = knife.getSecretKey(keyAlias, keyPassword);
    knife.replaceSecret(keyAlias, keyPassword, namespace.getString("new_secret"));

//    SecretKey newKey = new SecretKeySpec(newSecret, currentKey.getAlgorithm());
//    KeyStore.SecretKeyEntry newKeyEntry = new KeyStore.SecretKeyEntry(newKey);
//
//    knife.setSecretKey(namespace.getString("alias"), newKeyEntry, namespace.getString("password"));

    File outputFile = namespace.getString("out") == null ? namespace.get("keystore") : namespace.get("out");
    knife.save(outputFile, keyStorePassword);
  }
}
