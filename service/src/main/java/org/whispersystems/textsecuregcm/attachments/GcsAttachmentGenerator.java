/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.attachments;

import org.whispersystems.textsecuregcm.gcp.CanonicalRequest;
import org.whispersystems.textsecuregcm.gcp.CanonicalRequestGenerator;
import org.whispersystems.textsecuregcm.gcp.CanonicalRequestSigner;

import javax.annotation.Nonnull;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Map;

public class GcsAttachmentGenerator implements AttachmentGenerator {
  @Nonnull
  private final CanonicalRequestGenerator canonicalRequestGenerator;

  @Nonnull
  private final CanonicalRequestSigner canonicalRequestSigner;

  @Nonnull
  private final SecretKey encryptionKey;

  public GcsAttachmentGenerator(@Nonnull String domain, @Nonnull String email,
      int maxSizeInBytes, @Nonnull String pathPrefix, @Nonnull String rsaSigningKey, @Nonnull String encryptionKey)
      throws IOException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
    this.canonicalRequestGenerator = new CanonicalRequestGenerator(domain, email, maxSizeInBytes, pathPrefix);
    this.canonicalRequestSigner = new CanonicalRequestSigner(rsaSigningKey);
    this.encryptionKey = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");
  }

  @Override
  public Descriptor generateAttachment(final String key) {
    final ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
    final CanonicalRequest canonicalRequest = canonicalRequestGenerator.createFor(key, now);
    return new Descriptor(getHeaderMap(canonicalRequest), getSignedUploadLocation(canonicalRequest));
  }

  private String getSignedUploadLocation(@Nonnull CanonicalRequest canonicalRequest) {
    return "https://" + canonicalRequest.getDomain() + canonicalRequest.getResourcePath()
        + '?' + canonicalRequest.getCanonicalQuery()
        + "&X-Goog-Signature=" + canonicalRequestSigner.sign(canonicalRequest);
  }

  private static Map<String, String> getHeaderMap(@Nonnull CanonicalRequest canonicalRequest) {
    return Map.of(
        "host", canonicalRequest.getDomain(),
        "x-goog-content-length-range", "1," + canonicalRequest.getMaxSizeInBytes(),
        "x-goog-resumable", "start");
  }

  private byte[] encryptData(byte[] data) throws Exception {
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
    return cipher.doFinal(data);
  }
}
