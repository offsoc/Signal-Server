/*
 * Copyright 2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.whispersystems.textsecuregcm.entities.ECPreKey;
import org.whispersystems.textsecuregcm.entities.ECSignedPreKey;
import org.whispersystems.textsecuregcm.entities.KEMSignedPreKey;
import org.whispersystems.textsecuregcm.experiment.ExperimentEnrollmentManager;
import org.whispersystems.textsecuregcm.storage.DynamoDbExtensionSchema.Tables;
import org.whispersystems.textsecuregcm.tests.util.KeysHelper;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;

class KeysManagerTest {

  private KeysManager keysManager;
  private ExperimentEnrollmentManager experimentEnrollmentManager;

  private SingleUseKEMPreKeyStore singleUseKEMPreKeyStore;
  private PagedSingleUseKEMPreKeyStore pagedSingleUseKEMPreKeyStore;

  @RegisterExtension
  static final DynamoDbExtension DYNAMO_DB_EXTENSION = new DynamoDbExtension(
      Tables.EC_KEYS, Tables.PQ_KEYS, Tables.PAGED_PQ_KEYS,
      Tables.REPEATED_USE_EC_SIGNED_PRE_KEYS, Tables.REPEATED_USE_KEM_SIGNED_PRE_KEYS);

  @RegisterExtension
  static final S3LocalStackExtension S3_EXTENSION = new S3LocalStackExtension("testbucket");

  private static final UUID ACCOUNT_UUID = UUID.randomUUID();
  private static final byte DEVICE_ID = 1;

  private static final ECKeyPair IDENTITY_KEY_PAIR = ECKeyPair.generate();

  @BeforeEach
  void setup() {
    final DynamoDbAsyncClient dynamoDbAsyncClient = DYNAMO_DB_EXTENSION.getDynamoDbAsyncClient();
    experimentEnrollmentManager = mock(ExperimentEnrollmentManager.class);
    singleUseKEMPreKeyStore = new SingleUseKEMPreKeyStore(dynamoDbAsyncClient, Tables.PQ_KEYS.tableName());
    pagedSingleUseKEMPreKeyStore = new PagedSingleUseKEMPreKeyStore(dynamoDbAsyncClient,
        S3_EXTENSION.getS3Client(),
        DynamoDbExtensionSchema.Tables.PAGED_PQ_KEYS.tableName(),
        S3_EXTENSION.getBucketName());

    keysManager = new KeysManager(
        new SingleUseECPreKeyStore(dynamoDbAsyncClient, Tables.EC_KEYS.tableName()),
        singleUseKEMPreKeyStore,
        pagedSingleUseKEMPreKeyStore,
        new RepeatedUseECSignedPreKeyStore(dynamoDbAsyncClient, Tables.REPEATED_USE_EC_SIGNED_PRE_KEYS.tableName()),
        new RepeatedUseKEMSignedPreKeyStore(dynamoDbAsyncClient, Tables.REPEATED_USE_KEM_SIGNED_PRE_KEYS.tableName()),
        experimentEnrollmentManager);
  }

  @Test
  void storeEcOneTimePreKeys() {
    assertEquals(0, keysManager.getEcCount(ACCOUNT_UUID, DEVICE_ID).join(),
        "Initial pre-key count for an account should be zero");

    keysManager.storeEcOneTimePreKeys(ACCOUNT_UUID, DEVICE_ID, List.of(generateTestPreKey(1))).join();
    assertEquals(1, keysManager.getEcCount(ACCOUNT_UUID, DEVICE_ID).join());

    keysManager.storeEcOneTimePreKeys(ACCOUNT_UUID, DEVICE_ID, List.of(generateTestPreKey(1))).join();
    assertEquals(1, keysManager.getEcCount(ACCOUNT_UUID, DEVICE_ID).join(),
        "Repeatedly storing same key should have no effect");
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void storeKemOneTimePreKeysClearsOld(boolean inPagedExperiment) {
    final List<KEMSignedPreKey> oldPreKeys = List.of(generateTestKEMSignedPreKey(1));

    // Leave a key in the 'other' key store
    (inPagedExperiment
        ? singleUseKEMPreKeyStore.store(ACCOUNT_UUID, DEVICE_ID, oldPreKeys)
        : pagedSingleUseKEMPreKeyStore.store(ACCOUNT_UUID, DEVICE_ID, oldPreKeys))
        .join();

    when(experimentEnrollmentManager.isEnrolled(ACCOUNT_UUID, KeysManager.PAGED_KEYS_EXPERIMENT_NAME))
        .thenReturn(inPagedExperiment);


    final List<KEMSignedPreKey> newPreKeys = List.of(generateTestKEMSignedPreKey(2));
    keysManager.storeKemOneTimePreKeys(ACCOUNT_UUID, DEVICE_ID, newPreKeys).join();

    final int expectedPagedKeyCount = inPagedExperiment ? 1 : 0;
    final int expectedUnpagedKeyCount = 1 - expectedPagedKeyCount;
    assertEquals(1, keysManager.getPqCount(ACCOUNT_UUID, DEVICE_ID).join());
    assertEquals(expectedPagedKeyCount, pagedSingleUseKEMPreKeyStore.getCount(ACCOUNT_UUID, DEVICE_ID).join());
    assertEquals(expectedUnpagedKeyCount, singleUseKEMPreKeyStore.getCount(ACCOUNT_UUID, DEVICE_ID).join());

    final KEMSignedPreKey key = keysManager.takePQ(ACCOUNT_UUID, DEVICE_ID).join().orElseThrow();
    assertEquals(2, key.keyId());
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void storeKemOneTimePreKeys(boolean inPagedExperiment) {
    assertEquals(0, keysManager.getPqCount(ACCOUNT_UUID, DEVICE_ID).join(),
        "Initial pre-key count for an account should be zero");

    when(experimentEnrollmentManager.isEnrolled(ACCOUNT_UUID, KeysManager.PAGED_KEYS_EXPERIMENT_NAME))
        .thenReturn(inPagedExperiment);

    final int expectedPagedKeyCount = inPagedExperiment ? 1 : 0;
    final int expectedUnpagedKeyCount = 1 - expectedPagedKeyCount;

    keysManager.storeKemOneTimePreKeys(ACCOUNT_UUID, DEVICE_ID, List.of(generateTestKEMSignedPreKey(1))).join();
    assertEquals(1, keysManager.getPqCount(ACCOUNT_UUID, DEVICE_ID).join());
    assertEquals(expectedPagedKeyCount, pagedSingleUseKEMPreKeyStore.getCount(ACCOUNT_UUID, DEVICE_ID).join());
    assertEquals(expectedUnpagedKeyCount, singleUseKEMPreKeyStore.getCount(ACCOUNT_UUID, DEVICE_ID).join());

    keysManager.storeKemOneTimePreKeys(ACCOUNT_UUID, DEVICE_ID, List.of(generateTestKEMSignedPreKey(1))).join();
    assertEquals(1, keysManager.getPqCount(ACCOUNT_UUID, DEVICE_ID).join());
    assertEquals(expectedPagedKeyCount, pagedSingleUseKEMPreKeyStore.getCount(ACCOUNT_UUID, DEVICE_ID).join());
    assertEquals(expectedUnpagedKeyCount, singleUseKEMPreKeyStore.getCount(ACCOUNT_UUID, DEVICE_ID).join());
  }


  @Test
  void storeEcSignedPreKeys() {
    assertTrue(keysManager.getEcSignedPreKey(ACCOUNT_UUID, DEVICE_ID).join().isEmpty());

    final ECSignedPreKey signedPreKey = generateTestECSignedPreKey(1);

    keysManager.storeEcSignedPreKeys(ACCOUNT_UUID, DEVICE_ID, signedPreKey).join();

    assertEquals(Optional.of(signedPreKey), keysManager.getEcSignedPreKey(ACCOUNT_UUID, DEVICE_ID).join());
  }

  @Test
  void testTakeAccountAndDeviceId() {
    assertEquals(Optional.empty(), keysManager.takeEC(ACCOUNT_UUID, DEVICE_ID).join());

    final ECPreKey preKey = generateTestPreKey(1);

    keysManager.storeEcOneTimePreKeys(ACCOUNT_UUID, DEVICE_ID, List.of(preKey, generateTestPreKey(2))).join();

    final Optional<ECPreKey> takenKey = keysManager.takeEC(ACCOUNT_UUID, DEVICE_ID).join();
    assertEquals(Optional.of(preKey), takenKey);
    assertEquals(1, keysManager.getEcCount(ACCOUNT_UUID, DEVICE_ID).join());
  }

  @Test
  void testTakePQ() {
    assertEquals(Optional.empty(), keysManager.takeEC(ACCOUNT_UUID, DEVICE_ID).join());

    final KEMSignedPreKey preKey1 = generateTestKEMSignedPreKey(1);
    final KEMSignedPreKey preKey2 = generateTestKEMSignedPreKey(2);
    final KEMSignedPreKey preKeyLast = generateTestKEMSignedPreKey(1001);

    keysManager.storeKemOneTimePreKeys(ACCOUNT_UUID, DEVICE_ID, List.of(preKey1, preKey2)).join();
    keysManager.storePqLastResort(ACCOUNT_UUID, DEVICE_ID, preKeyLast).join();

    assertEquals(Optional.of(preKey1), keysManager.takePQ(ACCOUNT_UUID, DEVICE_ID).join());
    assertEquals(1, keysManager.getPqCount(ACCOUNT_UUID, DEVICE_ID).join());

    assertEquals(Optional.of(preKey2), keysManager.takePQ(ACCOUNT_UUID, DEVICE_ID).join());
    assertEquals(0, keysManager.getPqCount(ACCOUNT_UUID, DEVICE_ID).join());

    assertEquals(Optional.of(preKeyLast), keysManager.takePQ(ACCOUNT_UUID, DEVICE_ID).join());
    assertEquals(0, keysManager.getPqCount(ACCOUNT_UUID, DEVICE_ID).join());

    assertEquals(Optional.of(preKeyLast), keysManager.takePQ(ACCOUNT_UUID, DEVICE_ID).join());
    assertEquals(0, keysManager.getPqCount(ACCOUNT_UUID, DEVICE_ID).join());
  }

  @Test
  void takeWithExistingExperimentalKey() {
    // Put a key in the new store, even though we're not in the experiment. This simulates a take when operating
    // in mixed mode on experiment rollout
    pagedSingleUseKEMPreKeyStore.store(ACCOUNT_UUID, DEVICE_ID, List.of(generateTestKEMSignedPreKey(1))).join();

    assertEquals(1, keysManager.getPqCount(ACCOUNT_UUID, DEVICE_ID).join());
    assertEquals(1, keysManager.takePQ(ACCOUNT_UUID, DEVICE_ID).join().orElseThrow().keyId());
    assertEquals(0, keysManager.getPqCount(ACCOUNT_UUID, DEVICE_ID).join());
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void testDeleteSingleUsePreKeysByAccount(final boolean inPagedExperiment) {
    int keyId = 1;

    when(experimentEnrollmentManager.isEnrolled(ACCOUNT_UUID, KeysManager.PAGED_KEYS_EXPERIMENT_NAME))
        .thenReturn(inPagedExperiment);

    for (byte deviceId : new byte[] {DEVICE_ID, DEVICE_ID + 1}) {
      keysManager.storeEcOneTimePreKeys(ACCOUNT_UUID, deviceId, List.of(generateTestPreKey(keyId++))).join();
      keysManager.storeKemOneTimePreKeys(ACCOUNT_UUID, deviceId, List.of(generateTestKEMSignedPreKey(keyId++))).join();
      keysManager.storeEcSignedPreKeys(ACCOUNT_UUID, deviceId, generateTestECSignedPreKey(keyId++)).join();
      keysManager.storePqLastResort(ACCOUNT_UUID, deviceId, generateTestKEMSignedPreKey(keyId++)).join();
    }

    for (byte deviceId : new byte[] {DEVICE_ID, DEVICE_ID + 1}) {
      assertEquals(1, keysManager.getEcCount(ACCOUNT_UUID, deviceId).join());
      assertEquals(1, keysManager.getPqCount(ACCOUNT_UUID, deviceId).join());
      assertTrue(keysManager.getEcSignedPreKey(ACCOUNT_UUID, deviceId).join().isPresent());
      assertTrue(keysManager.getLastResort(ACCOUNT_UUID, deviceId).join().isPresent());
    }

    keysManager.deleteSingleUsePreKeys(ACCOUNT_UUID).join();

    for (byte deviceId : new byte[] {DEVICE_ID, DEVICE_ID + 1}) {
      assertEquals(0, keysManager.getEcCount(ACCOUNT_UUID, deviceId).join());
      assertEquals(0, keysManager.getPqCount(ACCOUNT_UUID, deviceId).join());
      assertTrue(keysManager.getEcSignedPreKey(ACCOUNT_UUID, deviceId).join().isPresent());
      assertTrue(keysManager.getLastResort(ACCOUNT_UUID, deviceId).join().isPresent());
    }
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void testDeleteSingleUsePreKeysByAccountAndDevice(final boolean inPagedExperiment) {
    int keyId = 1;

    when(experimentEnrollmentManager.isEnrolled(ACCOUNT_UUID, KeysManager.PAGED_KEYS_EXPERIMENT_NAME))
        .thenReturn(inPagedExperiment);

    for (byte deviceId : new byte[] {DEVICE_ID, DEVICE_ID + 1}) {
      keysManager.storeEcOneTimePreKeys(ACCOUNT_UUID, deviceId, List.of(generateTestPreKey(keyId++))).join();
      keysManager.storeKemOneTimePreKeys(ACCOUNT_UUID, deviceId, List.of(generateTestKEMSignedPreKey(keyId++))).join();
      keysManager.storeEcSignedPreKeys(ACCOUNT_UUID, deviceId, generateTestECSignedPreKey(keyId++)).join();
      keysManager.storePqLastResort(ACCOUNT_UUID, deviceId, generateTestKEMSignedPreKey(keyId++)).join();
    }

    for (byte deviceId : new byte[] {DEVICE_ID, DEVICE_ID + 1}) {
      assertEquals(1, keysManager.getEcCount(ACCOUNT_UUID, deviceId).join());
      assertEquals(1, keysManager.getPqCount(ACCOUNT_UUID, deviceId).join());
      assertTrue(keysManager.getEcSignedPreKey(ACCOUNT_UUID, deviceId).join().isPresent());
      assertTrue(keysManager.getLastResort(ACCOUNT_UUID, deviceId).join().isPresent());
    }

    keysManager.deleteSingleUsePreKeys(ACCOUNT_UUID, DEVICE_ID).join();

    assertEquals(0, keysManager.getEcCount(ACCOUNT_UUID, DEVICE_ID).join());
    assertEquals(0, keysManager.getPqCount(ACCOUNT_UUID, DEVICE_ID).join());
    assertTrue(keysManager.getEcSignedPreKey(ACCOUNT_UUID, DEVICE_ID).join().isPresent());
    assertTrue(keysManager.getLastResort(ACCOUNT_UUID, DEVICE_ID).join().isPresent());

    assertEquals(1, keysManager.getEcCount(ACCOUNT_UUID, (byte) (DEVICE_ID + 1)).join());
    assertEquals(1, keysManager.getPqCount(ACCOUNT_UUID, (byte) (DEVICE_ID + 1)).join());
    assertTrue(keysManager.getEcSignedPreKey(ACCOUNT_UUID, (byte) (DEVICE_ID + 1)).join().isPresent());
    assertTrue(keysManager.getLastResort(ACCOUNT_UUID, (byte) (DEVICE_ID + 1)).join().isPresent());
  }

  @Test
  void testStorePqLastResort() {
    final ECKeyPair identityKeyPair = ECKeyPair.generate();

    final byte deviceId2 = 2;
    final byte deviceId3 = 3;

    keysManager.storePqLastResort(ACCOUNT_UUID, DEVICE_ID, KeysHelper.signedKEMPreKey(1, identityKeyPair)).join();
    keysManager.storePqLastResort(ACCOUNT_UUID, (byte) 2, KeysHelper.signedKEMPreKey(2, identityKeyPair)).join();

    assertEquals(1L, keysManager.getLastResort(ACCOUNT_UUID, DEVICE_ID).join().orElseThrow().keyId());
    assertEquals(2L, keysManager.getLastResort(ACCOUNT_UUID, deviceId2).join().orElseThrow().keyId());
    assertFalse(keysManager.getLastResort(ACCOUNT_UUID, deviceId3).join().isPresent());

    keysManager.storePqLastResort(ACCOUNT_UUID, DEVICE_ID, KeysHelper.signedKEMPreKey(3, identityKeyPair)).join();
    keysManager.storePqLastResort(ACCOUNT_UUID, deviceId3, KeysHelper.signedKEMPreKey(4, identityKeyPair)).join();

    assertEquals(3L, keysManager.getLastResort(ACCOUNT_UUID, DEVICE_ID).join().orElseThrow().keyId(),
        "storing new last-resort keys should overwrite old ones");
    assertEquals(2L, keysManager.getLastResort(ACCOUNT_UUID, deviceId2).join().orElseThrow().keyId(),
        "storing new last-resort keys should leave untouched ones alone");
    assertEquals(4L, keysManager.getLastResort(ACCOUNT_UUID, deviceId3).join().orElseThrow().keyId(),
        "storing new last-resort keys should overwrite old ones");
  }

  private static ECPreKey generateTestPreKey(final long keyId) {
    return new ECPreKey(keyId, ECKeyPair.generate().getPublicKey());
  }

  private static ECSignedPreKey generateTestECSignedPreKey(final long keyId) {
    return KeysHelper.signedECPreKey(keyId, IDENTITY_KEY_PAIR);
  }

  private static KEMSignedPreKey generateTestKEMSignedPreKey(final long keyId) {
    return KeysHelper.signedKEMPreKey(keyId, IDENTITY_KEY_PAIR);
  }
}
