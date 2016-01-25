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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Objects;

public class KeyStoreKnife {

  private final KeyStore keyStore;

  private KeyStoreKnife(KeyStore keyStore) {
    this.keyStore = Objects.requireNonNull(keyStore, "Key store is null");
  }

  public KeyStore getKeyStore() {
    return keyStore;
  }

  public Key getKey(String alias, String password) {
    try {
      return keyStore.getKey(alias, password.toCharArray());
    } catch (Exception ex) {
      throw new KeyStoreKnifeException(String.format("Unable to read key (alias: %s)", alias), ex);
    }
  }

  public SecretKey getSecretKey(String alias, String password) {
    try {
      return (SecretKey) keyStore.getKey(alias, password.toCharArray());
    } catch (Exception ex) {
      throw new KeyStoreKnifeException(String.format("Unable to read key (alias: %s)", alias), ex);
    }
  }

  public void replaceSecret(String alias, String password, String newSecret, String encoding) {
    SecretKey key = getSecretKey(alias, password);
    replaceSecret(key, alias, password, newSecret, encoding);
  }

  public void replaceSecret(SecretKey currentKey, String alias, String password, String newSecret, String encoding) {
    byte[] newSecretBytes = new byte[0];
    switch(encoding.toLowerCase()) {
      case "base16":
        newSecretBytes = BaseEncoding.base16().decode(newSecret);
        break;
      case "base32":
        newSecretBytes = BaseEncoding.base32().decode(newSecret);
        break;
      case "base32_hex":
        newSecretBytes = BaseEncoding.base32Hex().decode(newSecret);
        break;
      case "base64":
        newSecretBytes = BaseEncoding.base64().decode(newSecret);
        break;
      case "base64_url":
        newSecretBytes = BaseEncoding.base64Url().decode(newSecret);
        break;
      case "plain":
      default:
        newSecretBytes = newSecret.getBytes(StandardCharsets.UTF_8);
        break;
    }

    SecretKey newKey = new SecretKeySpec(newSecretBytes, currentKey.getAlgorithm());
    KeyStore.SecretKeyEntry newKeyEntry = new KeyStore.SecretKeyEntry(newKey);
    setSecretKey(alias, newKeyEntry, password);
  }

  public void setSecretKey(String alias, KeyStore.SecretKeyEntry entry, String password) {
    try {
      KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(password.toCharArray());
      keyStore.setEntry(alias, entry, protection);
    } catch (Exception ex) {
      throw new KeyStoreKnifeException("Unable to set secret key", ex);
    }
  }

  public void save(File outputFile, String password) throws IOException {
    try {
      try (FileOutputStream output = new FileOutputStream(outputFile)) {
        keyStore.store(output, password.toCharArray());
      }
    } catch (Exception ex) {
      throw new KeyStoreKnifeException("Unable to save keystore", ex);
    }
  }

  public static KeyStoreKnife create(File keyStoreFile, String type, String password) {
    try {
      KeyStore keyStore = createKeyStore(type);

      try(FileInputStream input = new FileInputStream(keyStoreFile)) {
        keyStore.load(input, password.toCharArray());
      }

      return new KeyStoreKnife(keyStore);
    } catch (Exception ex) {
      throw new KeyStoreKnifeException(ex.getMessage(), ex);
    }
  }


  private static KeyStore createKeyStore(String algorithm) {
    try {
      return KeyStore.getInstance(algorithm);
    } catch (KeyStoreException ex) {
      throw new IllegalArgumentException(String.format("Key store type not found (type: %s)", algorithm), ex);
    }
  }
}
