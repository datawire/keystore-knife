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

package io.datawire.keystoreknife;


import io.datawire.app.Application;
import io.datawire.app.ApplicationConfiguration;
import io.datawire.app.Initializer;
import io.datawire.keystoreknife.command.ReplaceCommand;
import io.datawire.keystoreknife.command.ShowCommand;

public class KeyStoreKnifeApplication extends Application<ApplicationConfiguration> {

  KeyStoreKnifeApplication() {
    super("keystore-knife", ApplicationConfiguration.class);
  }

  @Override
  public void initialize(Initializer<ApplicationConfiguration> initializer) {
    initializer.addCommand(new ReplaceCommand());
    initializer.addCommand(new ShowCommand());
  }

  public static void main(String... args) {
    new KeyStoreKnifeApplication().run(args);
  }
}
