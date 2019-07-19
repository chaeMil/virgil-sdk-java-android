package com.virgilsecurity.sdk.androidutils;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
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
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class AndroidCipherTest {

    private static final String TEXT = "This is the best text ever";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String ANDROID_KEY_STORE_ALIAS = "AndroidKeyStoreTestAlias";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    @Before
    public void setup() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // Initial key generation
        final KeyGenerator keyGenerator = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

        final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(ANDROID_KEY_STORE_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
//                .setUserAuthenticationRequired(true) // TODO test how authentication works
                .build();

        keyGenerator.init(keyGenParameterSpec);
        keyGenerator.generateKey();
    }

    @Test
    public void encrypt_decrypt_with_android_aes_gcm()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException,
            CertificateException, IOException, KeyStoreException, UnrecoverableEntryException {

        // Load secret key
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);
        assertTrue(keyStore.containsAlias(ANDROID_KEY_STORE_ALIAS));

        final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
                .getEntry(ANDROID_KEY_STORE_ALIAS, null);

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
