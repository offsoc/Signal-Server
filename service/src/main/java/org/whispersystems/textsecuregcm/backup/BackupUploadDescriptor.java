/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.backup;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Map;

public record BackupUploadDescriptor(
    int cdn,
    String key,
    Map<String, String> headers,
    String signedUploadLocation) {

  public BackupUploadDescriptor(int cdn, String key, Map<String, String> headers, String signedUploadLocation, String encryptionKey) {
    this(cdn, encryptKey(key, encryptionKey), headers, signedUploadLocation);
  }

  private static String encryptKey(String key, String encryptionKey) {
    try {
      SecretKeySpec secretKey = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");
      Cipher cipher = Cipher.getInstance("AES");
      cipher.init(Cipher.ENCRYPT_MODE, secretKey);
      byte[] encryptedKey = cipher.doFinal(key.getBytes());
      return Base64.getEncoder().encodeToString(encryptedKey);
    } catch (Exception e) {
      throw new RuntimeException("Failed to encrypt key", e);
    }
  }
}
