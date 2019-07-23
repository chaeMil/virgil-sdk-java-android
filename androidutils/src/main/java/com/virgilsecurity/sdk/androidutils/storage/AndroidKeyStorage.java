/*
 * Copyright (c) 2015-2019, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.sdk.androidutils.storage;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import com.google.gson.Gson;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryAlreadyExistsException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyStorageException;
import com.virgilsecurity.sdk.storage.KeyEntry;
import com.virgilsecurity.sdk.storage.KeyStorage;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.Set;

/**
 * AndroidKeyStorage class uses AndroidKeyStore to generate symmetric key with which it encrypts Virgil private key,
 * while Virgil private key is used to encrypt KeyStorage itself. So to load key entry user has to be authenticated
 * on Android device. User authentication is up to developer.
 */
public class AndroidKeyStorage implements KeyStorage {

    private static final String VIRGIL_PUBLIC_KEY = "VIRGIL_PUBLIC_KEY";
    private static final String VIRGIL_PRIVATE_KEY_ENCRYPTED = "VIRGIL_PRIVATE_KEY_ENCRYPTED";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String ANDROID_KEY_STORE_ALIAS = "VirgilAndroidKeyStore";
    private static final int KEY_VALIDITY_DURATION = 5 * 60; // 5 min

    private String keysPath;
    private VirgilCrypto virgilCrypto;

    /**
     * Instantiates AndroidKeyStorage class.
     *
     * @param authenticationRequired is {@code true} by default. You can set it to {@code false} so the key storage
     *                               won't require user to be authenticated to use it.
     * @param keyValidityDuration default duration is 5 minutes. You can specify other duration of key validity in
     *                            seconds. After the time specified expired user has to be re-authenticated.
     * @param rootPath path which will be used to store keys.
     */
    public AndroidKeyStorage(boolean authenticationRequired, int keyValidityDuration, String rootPath) {
        this.keysPath = rootPath + File.separator + "VirgilSecurity" + File.separator + "Keys";
        virgilCrypto = new VirgilCrypto();

        try {
            final KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);

            if (!keyStore.containsAlias(ANDROID_KEY_STORE_ALIAS)) {
                generateAndSaveSymmetricKey(authenticationRequired, keyValidityDuration);
                generateAndSaveVirgilKeys();
            }
        } catch (CertificateException | NoSuchAlgorithmException | IOException | KeyStoreException
                | NoSuchProviderException | InvalidAlgorithmParameterException | UnrecoverableEntryException
                | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException
                | InvalidKeyException exception) {

            throw new KeyStorageException(exception.getMessage() == null ? exception.getMessage()
                    : "Error occurred while initializing android key storage.");
        } catch (CryptoException exception) {
            throw new IllegalStateException("Error generating Virgil keys");
        }
    }

    /**
     * Instantiates AndroidKeyStorage class. Default key validity time (after which user has to be re-authenticated)
     * is 5 minutes.
     *
     * @param authenticationRequired is {@code true} by default. You can set it to {@code false} so the key storage
     *                               won't require user to be authenticated to use it.
     */
    public AndroidKeyStorage(boolean authenticationRequired) {
        this(authenticationRequired, KEY_VALIDITY_DURATION, System.getProperty("user.home"));
    }

    /**
     * Instantiates AndroidKeyStorage class. {@code authenticationRequired} is automatically true, because in other case
     * {@code keyValidityDuration} makes no sense.
     *
     * @param keyValidityDuration default duration is 5 minutes. You can specify other duration of key validity in
     *                            seconds. After the time specified expired user has to be re-authenticated.
     */
    public AndroidKeyStorage(int keyValidityDuration) {
        this(true, keyValidityDuration, System.getProperty("user.home"));
    }

    /**
     * Instantiates AndroidKeyStorage class. Default key validity time (after which user has to be re-authenticated)
     * is 5 minutes.
     *
     * @param rootPath path which will be used to store keys.
     */
    public AndroidKeyStorage(String rootPath) {
        this(true, KEY_VALIDITY_DURATION, rootPath);
    }

    /**
     * Instantiates AndroidKeyStorage class. Default key validity time (after which user has to be re-authenticated)
     * is 5 minutes.
     */
    public AndroidKeyStorage() {
        this(true, KEY_VALIDITY_DURATION, System.getProperty("user.home"));
    }

    @Override
    public void delete(String keyName) {
        if (!exists(keyName)) {
            throw new KeyEntryNotFoundException();
        }

        // TODO check whether user is authenticated

        final File file = new File(keysPath, keyName.toLowerCase());
        final boolean isDeleted = file.delete();

        if (!isDeleted) {
            throw new IllegalStateException("Cannot delete \'" + keyName + "\' key.");
        }
    }

    @Override
    public boolean exists(String keyName) {
        if (keyName == null) {
            return false;
        }

        // TODO check whether user is authenticated

        final File file = new File(keysPath, keyName.toLowerCase());
        return file.exists();
    }

    // TODO check when UserNotAuthenticatedException is thrown
    @Override
    public KeyEntry load(String keyName) {
        if (!exists(keyName)) {
            throw new KeyEntryNotFoundException();
        }

        File file = new File(keysPath, keyName.toLowerCase());
        try (FileInputStream is = new FileInputStream(file)) {
            final ByteArrayOutputStream os = new ByteArrayOutputStream();

            final byte[] buffer = new byte[4096];
            int n;
            while (-1 != (n = is.read(buffer))) {
                os.write(buffer, 0, n);
            }

            final byte[] encryptedEntryData = os.toByteArray();
            final byte[] entryData = decryptWithVirgilKey(encryptedEntryData);

            final AndroidKeyEntry entry = new Gson().fromJson(new String(entryData, Charset.forName("UTF-8")),
                    AndroidKeyEntry.class);
            entry.setName(keyName);

            return entry;
        } catch (Exception e) {
            throw new KeyStorageException(e);
        }
    }

    @Override
    public Set<String> names() {

        // TODO check whether user is authenticated

        final File dir = new File(keysPath);
        final Set<String> names = new HashSet<>();
        if (dir.exists() && dir.isDirectory()) {
            for (File file : dir.listFiles()) {
                names.add(file.getName());
            }
        }
        return names;
    }

    @Override
    public void store(KeyEntry keyEntry) {
        final File dir = new File(keysPath);

        if (dir.exists()) {
            if (!dir.isDirectory()) {
                throw new IllegalArgumentException("\'" + keysPath + "\' is not a directory");
            }
        } else {
            boolean dirCreated = dir.mkdirs();

            if (!dirCreated) {
                throw new IllegalStateException("Cannot create directory in path: \'" + keysPath + "\'");
            }
        }

        final String name = keyEntry.getName();
        if (exists(name)) {
            throw new KeyEntryAlreadyExistsException();
        }

        final KeyEntry entry;
        if (keyEntry instanceof AndroidKeyEntry) {
            entry = keyEntry;
        } else {
            entry = new AndroidKeyEntry(keyEntry.getName(), keyEntry.getValue());
            entry.setMeta(keyEntry.getMeta());
        }

        final String json = new Gson().toJson(entry);
        final File file = new File(dir, name.toLowerCase());
        try (FileOutputStream os = new FileOutputStream(file)) {
            final byte[] encryptedEntryData = encryptWithVirgilKey(json.getBytes(Charset.forName("UTF-8")));
            os.write(encryptedEntryData);
        } catch (Exception e) {
            throw new KeyStorageException(e);
        }
    }

    @Override
    public KeyEntry createEntry(String name, byte[] value) {
        return new AndroidKeyEntry(name, value);
    }

    @Override
    public void update(final KeyEntry keyEntry) {
        final String keyName = keyEntry.getName();
        if (!exists(keyName)) {
            throw new KeyEntryNotFoundException();
        }
        delete(keyName);
        store(keyEntry);
    }

    private void generateAndSaveVirgilKeys()
            throws CertificateException, UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException,
            IOException, CryptoException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException,
            InvalidKeyException {

        final VirgilKeyPair virgilKeyPair = virgilCrypto.generateKeyPair();

        final byte[] publicKeyData = virgilCrypto.exportPublicKey(virgilKeyPair.getPublicKey());
        final AndroidKeyEntry publicKeyEntry = new AndroidKeyEntry(VIRGIL_PUBLIC_KEY, publicKeyData);
        store(publicKeyEntry);

        final SecretKey secretKey = loadSymmetricKey();
        final byte[] privateKeyData = virgilCrypto.exportPrivateKey(virgilKeyPair.getPrivateKey());
        byte[] encryptedPrivateKeyData = encryptWithSymmetricKey(secretKey, privateKeyData);
        final AndroidKeyEntry encryptedPrivateKeyEntry =
                new AndroidKeyEntry(VIRGIL_PRIVATE_KEY_ENCRYPTED, encryptedPrivateKeyData);
        store(encryptedPrivateKeyEntry);
    }

    private void generateAndSaveSymmetricKey(boolean authenticationRequired, int keyValidityDuration)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        final KeyGenerator keyGenerator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

        final KeyGenParameterSpec keyGenParameterSpec =
                new KeyGenParameterSpec.Builder(ANDROID_KEY_STORE_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setUserAuthenticationValidityDurationSeconds(keyValidityDuration)
                        .setUserAuthenticationRequired(authenticationRequired)
                        .build();

        keyGenerator.init(keyGenParameterSpec);
        keyGenerator.generateKey();
    }

    private byte[] encryptWithVirgilKey(byte[] data) throws CryptoException {
        final AndroidKeyEntry publicKeyEntry = (AndroidKeyEntry) load(VIRGIL_PUBLIC_KEY);
        final VirgilPublicKey publicKey = virgilCrypto.importPublicKey(publicKeyEntry.getValue());

        return virgilCrypto.encrypt(data, publicKey);
    }

    private byte[] decryptWithVirgilKey(byte[] data)
            throws CertificateException, UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException,
            IOException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException,
            InvalidAlgorithmParameterException, CryptoException {

        final AndroidKeyEntry encryptedPrivateKeyEntry = (AndroidKeyEntry) load(VIRGIL_PRIVATE_KEY_ENCRYPTED);
        final byte[] encryptedPrivateKeyData = encryptedPrivateKeyEntry.getValue();
        final SecretKey secretKey = loadSymmetricKey();
        final byte[] privateKeyData = decryptWithSymmetricKey(secretKey, encryptedPrivateKeyData);
        final VirgilPrivateKey privateKey = virgilCrypto.importPrivateKey(privateKeyData).getPrivateKey();

        return virgilCrypto.decrypt(data, privateKey);
    }

    private byte[] encryptWithSymmetricKey(SecretKey secretKey, byte[] data)
            throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException,
            NoSuchAlgorithmException {

        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        return cipher.doFinal(data);
    }

    private byte[] decryptWithSymmetricKey(SecretKey secretKey, byte[] data)
            throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, InvalidAlgorithmParameterException {

        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        final byte[] encryptionIv = cipher.getIV();

        final GCMParameterSpec spec = new GCMParameterSpec(128, encryptionIv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        return cipher.doFinal(data);
    }

    private SecretKey loadSymmetricKey()
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException,
            UnrecoverableEntryException {

        final KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);

        if (keyStore.containsAlias(ANDROID_KEY_STORE_ALIAS)) {
            throw new IllegalStateException("Cannot load symmetric key. "
                    + "Possibly you have deleted it with KeyStore instance by yourself.");
        }

        final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
                .getEntry(ANDROID_KEY_STORE_ALIAS, null); // TODO test when fingerprint/pattern has been changed

        return secretKeyEntry.getSecretKey();
    }
}
