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


import com.google.common.io.BaseEncoding;
import io.datawire.keystoreknife.exception.KeyStoreKnifeException;
import io.datawire.util.test.Fixtures;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.util.Properties;

import static org.assertj.core.api.Assertions.*;

public class KeyStoreKnifeTest {

  private final Fixtures fixtures = new Fixtures();

  @Rule
  public TemporaryFolder temporaryStorage = new TemporaryFolder();

  private Properties keyStoreProperties;
  private File keyStoreFile;
  private String keyStoreType;
  private String keyStorePassword;
  private String keyAlias;
  private String keyPassword;

  @Before
  public void setup() throws IOException {
    keyStoreProperties = loadProperties("keystore.properties");
    keyStoreFile = new File(fixtures.getFixtureFilePath("keystore.jceks"));
    keyStoreType = keyStoreProperties.getProperty("keyStoreType");
    keyStorePassword = keyStoreProperties.getProperty("keyStorePassword");
    keyAlias = keyStoreProperties.getProperty("alias");
    keyPassword = keyStoreProperties.getProperty("password");
  }

  @Test
  public void create_invalidKeyStore_throwsKeyStoreKnifeException() {
    try {
      KeyStoreKnife.create(
          new File(fixtures.getFixtureFilePath("not_a_real_keystore.jceks")), "jceks", "DOES_NOT_MATTER");
      failBecauseExceptionWasNotThrown(KeyStoreKnifeException.class);
    } catch (KeyStoreKnifeException ex) {
      assertThat(ex).hasCauseInstanceOf(IOException.class).hasMessage("Invalid keystore format");
    }
  }

  @Test
  public void create_invalidKeyStorePassword_throwsKeyStoreKnifeException() {
    try {
      KeyStoreKnife.create(
          new File(fixtures.getFixtureFilePath("keystore.jceks")), "jceks", "INVALID_PASSWORD");
      failBecauseExceptionWasNotThrown(KeyStoreKnifeException.class);
    } catch (KeyStoreKnifeException ex) {
      assertThat(ex).hasCauseInstanceOf(IOException.class)
          .hasMessage("Keystore was tampered with, or password was incorrect");
    }
  }

  @Test
  public void create_validKeyStore_ReturnKnife() throws Exception {
    KeyStoreKnife knife = KeyStoreKnife.create(keyStoreFile, keyStoreType, keyStorePassword);
    assertThat(knife).isNotNull();
  }

  @Test
  public void getSecretKey_keyExistsForAlias_ReturnSecretKey() throws Exception {
    KeyStoreKnife knife = KeyStoreKnife.create(keyStoreFile, keyStoreType, keyStorePassword);
    SecretKey knownSecret = knife.getSecretKey(keyAlias, keyPassword);

    assertThat(knownSecret).isNotNull();
    assertThat(knownSecret.getAlgorithm()).isEqualTo("HmacSHA256");
  }

  @Test
  public void getSecretKey_keyDoesNotExistForAlias_ThrowsKeyStoreKnifeException() throws Exception {
    KeyStoreKnife knife = KeyStoreKnife.create(keyStoreFile, keyStoreType, keyStorePassword);
    assertThat(knife.getSecretKey("UNKNOWN_ALIAS", keyPassword)).isNull();
  }

  @Test
  public void replaceSecretKey_WithPlain_replacesSecretKey() throws Exception {
    KeyStoreKnife knife = KeyStoreKnife.create(keyStoreFile, keyStoreType, keyStorePassword);
    SecretKey original = knife.getSecretKey(keyAlias, keyPassword);

    String newKeySecret = "applesauce";
    knife.replaceSecret(keyAlias, keyPassword, newKeySecret, "plain");

    SecretKey modified = knife.getSecretKey(keyAlias, keyPassword);
    assertThat(modified.getAlgorithm()).isEqualTo(original.getAlgorithm());
    assertThat(modified.getEncoded()).isNotEqualTo(original.getEncoded());
    assertThat(new String(modified.getEncoded())).isEqualTo(newKeySecret);
  }

  @Test
  public void replaceSecretKey_WithBase64Url_replacesSecretKey() throws Exception {
    KeyStoreKnife knife = KeyStoreKnife.create(keyStoreFile, keyStoreType, keyStorePassword);
    SecretKey original = knife.getSecretKey(keyAlias, keyPassword);

    String newKeySecret = "VjXkMykA8npGE6xXki24b-yfsTGsVmkCLAADPKHgeQyuF01RS-ES5DOfi_OhA6pa";
    knife.replaceSecret(keyAlias, keyPassword, newKeySecret, "base64_url");

    SecretKey modified = knife.getSecretKey(keyAlias, keyPassword);
    assertThat(modified.getAlgorithm()).isEqualTo(original.getAlgorithm());
    assertThat(modified.getEncoded()).isNotEqualTo(original.getEncoded());
    assertThat(BaseEncoding.base64Url().encode(modified.getEncoded())).isEqualTo(newKeySecret);
  }

  @Test
  public void saveKeyStore() throws IOException {
    KeyStoreKnife knife = KeyStoreKnife.create(keyStoreFile, keyStoreType, keyStorePassword);

    String newKeySecret = "applesauce";
    knife.replaceSecret(keyAlias, keyPassword, newKeySecret, "plain");

    File temporaryKeyStoreFile = temporaryStorage.newFile();

    knife.save(temporaryKeyStoreFile, keyStorePassword);

    KeyStoreKnife knifeForUpdatedKeyStore = KeyStoreKnife.create(temporaryKeyStoreFile, keyStoreType, keyStorePassword);
    SecretKey updatedAndSavedKey = knifeForUpdatedKeyStore.getSecretKey(keyAlias, keyPassword);

    assertThat(new String(updatedAndSavedKey.getEncoded())).isEqualTo(newKeySecret);
  }

  private Properties loadProperties(String propertiesFixture) throws IOException {
    Properties result = new Properties();
    result.load(fixtures.loadFixture(propertiesFixture));
    return result;
  }

  private KeyStore loadKeyStore(File file, String type, String password) throws Exception {
    KeyStore keyStore = KeyStore.getInstance(type);

    try(FileInputStream input = new FileInputStream(file)) {
      keyStore.load(input, password.toCharArray());
    }

    return keyStore;
  }
}
