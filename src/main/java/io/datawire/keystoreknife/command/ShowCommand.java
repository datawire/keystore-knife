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


import com.google.common.io.BaseEncoding;
import io.datawire.keystoreknife.KeyStoreKnife;
import io.datawire.app.Initializer;
import io.datawire.app.command.Command;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.Namespace;
import net.sourceforge.argparse4j.inf.Subparser;

import java.security.Key;

public class ShowCommand extends Command {

  public ShowCommand() {
    super("show-secret", "Show an existing secret key");
  }

  @Override
  public void configure(Subparser subparser) {
    subparser.addArgument("keystore")
        .help("the keystore to open and modify")
        .type(Arguments.fileType().verifyCanRead());

    subparser.addArgument("--keystore-type").setDefault("JCEKS");
    subparser.addArgument("keystore_password").help("the keystore password");
    subparser.addArgument("alias").help("the alias of the secret being replaced");
    subparser.addArgument("password").help("the password protecting the secret");
  }

  @Override
  public void run(Initializer<?> initializer, Namespace namespace) throws Exception {
    KeyStoreKnife keystore = KeyStoreKnife.create(
        namespace.get("keystore"), namespace.getString("keystore_type"), namespace.getString("keystore_password"));

    Key key = keystore.getKey(namespace.getString("alias"), namespace.getString("password"));

    StringBuilder result = new StringBuilder();
    result.append("Key: ").append(namespace.getString("alias"))
        .append(System.lineSeparator())
        .append(System.lineSeparator());

    result.append("Hex        -> ").append(BaseEncoding.base16().encode(key.getEncoded()).toLowerCase())
        .append(System.lineSeparator());

    result.append("Base64     -> ").append(BaseEncoding.base64().encode(key.getEncoded())).append(System.lineSeparator());
    result.append("Base64 URL -> ").append(BaseEncoding.base64Url().encode(key.getEncoded())).append(System.lineSeparator());

    System.out.println(result.toString());
  }
}
