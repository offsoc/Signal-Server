/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.backup;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * Descriptor for a single copy-and-encrypt operation
 *
 * @param sourceCdn            The cdn of the object to copy
 * @param sourceKey            The mediaId within the cdn of the object to copy
 * @param sourceLength         The length of the object to copy
 * @param encryptionParameters Encryption parameters to double encrypt the object
 * @param destinationMediaId   The mediaId of the destination object
 */
public record CopyParameters(
    int sourceCdn,
    String sourceKey,
    int sourceLength,
    MediaEncryptionParameters encryptionParameters,
    byte[] destinationMediaId) {

  /**
   * @return The size of the double-encrypted destination object after it is copied
   */
  long destinationObjectSize() {
    return encryptionParameters().outputSize(sourceLength());
  }

  private byte[] encryptData(byte[] data, String encryptionKey) throws Exception {
    SecretKeySpec secretKey = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    return cipher.doFinal(data);
  }
}
