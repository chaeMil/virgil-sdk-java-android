package com.virgilsecurity.sdk.androidutils;

import android.app.KeyguardManager;
import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class AndroidCipherTest {

    private static final String TEXT = "This is the best text ever";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private String androidKeyStoreAlias = "AndroidKeyStoreTestAliasAuth4";
    private KeyguardManager keyguardManager;

    @Before
    public void setup() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        androidKeyStoreAlias = UUID.randomUUID().toString().substring(0, 12);

        // Initial key generation
        final KeyGenerator keyGenerator = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

        final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(androidKeyStoreAlias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
//                .setUnlockedDeviceRequired(true) // TODO check on device
                .setUserAuthenticationValidityDurationSeconds(120) // TODO do we need at lease one fingerprint?
                .setUserAuthenticationRequired(true)
                .build();

        keyGenerator.init(keyGenParameterSpec);
        keyGenerator.generateKey();

        keyguardManager = (KeyguardManager) InstrumentationRegistry.getContext().getSystemService(Context.KEYGUARD_SERVICE);

        assertTrue(keyguardManager.isDeviceSecure());

//        FingerprintManagerCompat fingerprintManager =
//                FingerprintManagerCompat.from(InstrumentationRegistry.getContext());
//
//        assertTrue(fingerprintManager.hasEnrolledFingerprints());
    }

    @Test
    public void encrypt_decrypt_with_android_aes_gcm()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException,
            CertificateException, IOException, KeyStoreException, UnrecoverableEntryException {

        // Load secret key
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);
        assertTrue(keyStore.containsAlias(androidKeyStoreAlias));

        final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
                .getEntry(androidKeyStoreAlias, null);

        final SecretKey secretKey = secretKeyEntry.getSecretKey();

        // Encryption
        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encryptionIv = cipher.getIV();

        byte[] encryptedData = cipher.doFinal(TEXT.getBytes(StandardCharsets.UTF_8));


        // Decryption
        final GCMParameterSpec spec = new GCMParameterSpec(128, encryptionIv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        final byte[] decodedData = cipher.doFinal(encryptedData);
        final String decryptedString = new String(decodedData, StandardCharsets.UTF_8);

        assertEquals(TEXT, decryptedString);
    }
}
