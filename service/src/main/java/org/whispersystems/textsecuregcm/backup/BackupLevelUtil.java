/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.backup;

import org.signal.libsignal.zkgroup.backups.BackupLevel;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class BackupLevelUtil {

  private static final String AES = "AES";
  private static final int AES_KEY_SIZE = 256;
  private static final String AES_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";

  private final SecretKey encryptionKey;

  public BackupLevelUtil(String userDefinedKey) {
    this.encryptionKey = generateKey(userDefinedKey);
  }

  public static BackupLevel fromReceiptLevel(long receiptLevel) {
    try {
      return BackupLevel.fromValue(Math.toIntExact(receiptLevel));
    } catch (ArithmeticException e) {
      throw new IllegalArgumentException("Invalid receipt level: " + receiptLevel);
    }
  }

  private SecretKey generateKey(String userDefinedKey) {
    try {
      byte[] keyBytes = userDefinedKey.getBytes();
      return new SecretKeySpec(keyBytes, 0, AES_KEY_SIZE / 8, AES);
    } catch (Exception e) {
      throw new RuntimeException("Error generating encryption key", e);
    }
  }

  public String encrypt(String data) {
    try {
      Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
      byte[] encryptedBytes = cipher.doFinal(data.getBytes());
      return Base64.getEncoder().encodeToString(encryptedBytes);
    } catch (Exception e) {
      throw new RuntimeException("Error encrypting data", e);
    }
  }

  public String decrypt(String encryptedData) {
    try {
      Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
      cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
      byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
      byte[] decryptedBytes = cipher.doFinal(decodedBytes);
      return new String(decryptedBytes);
    } catch (Exception e) {
      throw new RuntimeException("Error decrypting data", e);
    }
  }
}
