package com.virgilsecurity.sdk.androidutils.storage;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryAlreadyExistsException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyStorageException;
import com.virgilsecurity.sdk.storage.KeyEntry;
import com.virgilsecurity.sdk.storage.KeyStorage;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.InvalidPathException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.Set;

/**
 * AndroidKeyStorage class.
 */
public class AndroidKeyStorage implements KeyStorage {

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String ANDROID_KEY_STORE_ALIAS = "VirgilAndroidKeyStore";
    private static final int KEY_VALIDITY_DURATION = 5 * 60; // 5 sec

    private String keysPath;
    private VirgilCrypto virgilCrypto;
    private KeyStore keyStore;

    public AndroidKeyStorage(String rootPath) {
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);

            if (!keyStore.containsAlias(ANDROID_KEY_STORE_ALIAS)) {
                final VirgilKeyPair virgilKeyPair = virgilCrypto.generateKeyPair(); // Generate only if keys are not generated yet
                // TODO Save virgil keys

                final KeyGenerator keyGenerator =
                        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

                final KeyGenParameterSpec keyGenParameterSpec =
                        new KeyGenParameterSpec.Builder(ANDROID_KEY_STORE_ALIAS,
                                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setUserAuthenticationValidityDurationSeconds(KEY_VALIDITY_DURATION)
                                .setInvalidatedByBiometricEnrollment()
                        .setUserAuthenticationRequired(true)
                        .build();

                keyGenerator.init(keyGenParameterSpec);
                keyGenerator.generateKey();
            }
        } catch (CertificateException | NoSuchAlgorithmException | IOException | KeyStoreException
                | NoSuchProviderException | InvalidAlgorithmParameterException exception) {

            throw new KeyStorageException(exception.getMessage() == null ? exception.getMessage()
                    : "Error while loading key storage.");
        } catch (CryptoException exception) {

        }

        this.keysPath = rootPath + File.separator + "VirgilSecurity" + File.separator + "Keys";
    }

    public AndroidKeyStorage() {
        this(System.getProperty("user.home"));
    }

    @Override
    public void delete(String keyName) {
        if (!exists(keyName)) {
            throw new KeyEntryNotFoundException();
        }

        File file = new File(keysPath, keyName.toLowerCase());
        file.delete();
    }

    @Override
    public boolean exists(String keyName) {
        if (keyName == null) {
            return false;
        }
        File file = new File(keysPath, keyName.toLowerCase());
        return file.exists();
    }

    @Override
    public KeyEntry load(String keyName) {
        if (!exists(keyName)) {
            throw new KeyEntryNotFoundException();
        }

        File file = new File(keysPath, keyName.toLowerCase());
        try (FileInputStream is = new FileInputStream(file)) {
            ByteArrayOutputStream os = new ByteArrayOutputStream();

            byte[] buffer = new byte[4096];
            int n = 0;
            while (-1 != (n = is.read(buffer))) {
                os.write(buffer, 0, n);
            }

            byte[] bytes = os.toByteArray();

            JsonKeyEntry entry = getGson().fromJson(new String(bytes, Charset.forName("UTF-8")),
                    JsonKeyEntry.class);
            entry.setName(keyName);

            return entry;
        } catch (Exception e) {
            throw new KeyStorageException(e);
        }
    }

    @Override
    public Set<String> names() {
        File dir = new File(keysPath);
        Set<String> names = new HashSet<>();
        if (dir.exists() && dir.isDirectory()) {
            for (File file : dir.listFiles()) {
                names.add(file.getName());
            }
        }
        return names;
    }

    @Override
    public void store(KeyEntry keyEntry) {
        File dir = new File(keysPath);

        if (dir.exists()) {
            if (!dir.isDirectory()) {
                throw new InvalidPathException(keysPath, "Is not a directory");
            }
        } else {
            dir.mkdirs();
        }

        String name = keyEntry.getName();
        if (exists(name)) {
            throw new KeyEntryAlreadyExistsException();
        }

        KeyEntry entry;
        if (keyEntry instanceof JsonKeyEntry) {
            entry = keyEntry;
        } else {
            entry = new JsonKeyEntry(keyEntry.getName(), keyEntry.getValue());
            entry.setMeta(keyEntry.getMeta());
        }

        String json = getGson().toJson(entry);
        File file = new File(dir, name.toLowerCase());
        try (FileOutputStream os = new FileOutputStream(file)) {
            os.write(json.getBytes(Charset.forName("UTF-8")));
        } catch (Exception e) {
            throw new KeyStorageException(e);
        }
    }

    private Gson getGson() {
        GsonBuilder builder = new GsonBuilder();
        Gson gson = builder.create();

        return gson;
    }

    @Override
    public KeyEntry createEntry(String name, byte[] value) {
        return new JsonKeyEntry(name, value);
    }

    @Override
    public void update(final KeyEntry keyEntry) {
        encryptPerformDecrypt(new EncryptedOperation() {
            @Override
            public void perform() {
                String keyName = keyEntry.getName();
                if (!exists(keyName)) {
                    throw new KeyEntryNotFoundException();
                }
                delete(keyName);
                store(keyEntry);
            }
        });
    }

    /**
     * Decrypts storage then performs provided operation, after that encrypts storage again.
     *
     * @param operation To perform on decrypt
     */
    private void encryptPerformDecrypt(EncryptedOperation operation) {
        SecretKey secretKey = getStorageKey();
        // get virgil key pair
        // decrypt virgil private key
        virgilCrypto.decrypt(keyStorage, virgilPrivateKey);
        operation.perform();
        virgilCrypto.encrypt(keyStorage, virgilPublicKey);
    }

    private interface EncryptedOperation {

        void perform();
    }
}
