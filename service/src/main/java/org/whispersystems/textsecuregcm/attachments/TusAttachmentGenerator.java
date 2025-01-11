/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.attachments;

import org.apache.http.HttpHeaders;
import org.whispersystems.textsecuregcm.auth.ExternalServiceCredentials;
import org.whispersystems.textsecuregcm.auth.ExternalServiceCredentialsGenerator;
import org.whispersystems.textsecuregcm.util.HeaderUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Base64;
import java.util.Map;

public class TusAttachmentGenerator implements AttachmentGenerator {

  private static final String ATTACHMENTS = "attachments";

  final ExternalServiceCredentialsGenerator credentialsGenerator;
  final String tusUri;
  private final SecretKeySpec encryptionKey;

  public TusAttachmentGenerator(final TusConfiguration cfg, final String encryptionKey) {
    this.tusUri = cfg.uploadUri();
    this.credentialsGenerator = credentialsGenerator(Clock.systemUTC(), cfg);
    this.encryptionKey = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");
  }

  private static ExternalServiceCredentialsGenerator credentialsGenerator(final Clock clock, final TusConfiguration cfg) {
    return ExternalServiceCredentialsGenerator
        .builder(cfg.userAuthenticationTokenSharedSecret())
        .prependUsername(false)
        .withClock(clock)
        .build();
  }

  @Override
  public Descriptor generateAttachment(final String key) {
    final ExternalServiceCredentials credentials = credentialsGenerator.generateFor(ATTACHMENTS + "/" + key);
    final String b64Key = Base64.getEncoder().encodeToString(key.getBytes(StandardCharsets.UTF_8));
    final Map<String, String> headers = Map.of(
        HttpHeaders.AUTHORIZATION, HeaderUtils.basicAuthHeader(credentials),
        "Upload-Metadata", String.format("filename %s", b64Key)
    );
    return new Descriptor(headers, tusUri + "/" +  ATTACHMENTS);
  }

  private byte[] encryptData(byte[] data) throws Exception {
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
    return cipher.doFinal(data);
  }
}
