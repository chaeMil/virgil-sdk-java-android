//package com.virgilsecurity.sdk.androidutils.storage;
//
//import android.security.keystore.KeyGenParameterSpec;
//import android.security.keystore.KeyProperties;
//import com.google.gson.Gson;
//import com.google.gson.GsonBuilder;
//import com.virgilsecurity.sdk.crypto.VirgilCrypto;
//import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
//import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryAlreadyExistsException;
//import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
//import com.virgilsecurity.sdk.crypto.exceptions.KeyStorageException;
//import com.virgilsecurity.sdk.storage.KeyEntry;
//import com.virgilsecurity.sdk.storage.KeyStorage;
//
//import javax.crypto.Cipher;
//import javax.crypto.KeyGenerator;
//import javax.crypto.SecretKey;
//import java.io.ByteArrayOutputStream;
//import java.io.File;
//import java.io.FileInputStream;
//import java.io.FileOutputStream;
//import java.nio.charset.Charset;
//import java.nio.file.InvalidPathException;
//import java.util.HashSet;
//import java.util.Set;
//
///**
// * AndroidKeyStorage class.
// */
//public class AndroidKeyStorage implements KeyStorage {
//
//    private String keysPath;
//    private VirgilCrypto virgilCrypto;
//
//    public AndroidKeyStorage(String rootPath) {
//        final KeyGenerator keyGenerator = KeyGenerator
//                .getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
//
//        final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(alias,
//                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
//                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
//                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
//                .build();
//
//        keyGenerator.init(keyGenParameterSpec);
//        final SecretKey secretKey = keyGenerator.generateKey();
//
//        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
//        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
//
//        StringBuilder path = new StringBuilder(rootPath);
//        path.append(File.separator).append("VirgilSecurity");
//        path.append(File.separator).append("Keys");
//
//        this.keysPath = path.toString();
//
//        VirgilKeyPair virgilKeyPair = virgilCrypto.generateKeyPair(); // Generate only if keys are not generated yet
//    }
//
//    public AndroidKeyStorage() {
//        this(System.getProperty("user.home"));
//    }
//
//    @Override
//    public void delete(String keyName) {
//        if (!exists(keyName)) {
//            throw new KeyEntryNotFoundException();
//        }
//
//        File file = new File(keysPath, keyName.toLowerCase());
//        file.delete();
//    }
//
//    @Override
//    public boolean exists(String keyName) {
//        if (keyName == null) {
//            return false;
//        }
//        File file = new File(keysPath, keyName.toLowerCase());
//        return file.exists();
//    }
//
//    @Override
//    public KeyEntry load(String keyName) {
//        if (!exists(keyName)) {
//            throw new KeyEntryNotFoundException();
//        }
//
//        File file = new File(keysPath, keyName.toLowerCase());
//        try (FileInputStream is = new FileInputStream(file)) {
//            ByteArrayOutputStream os = new ByteArrayOutputStream();
//
//            byte[] buffer = new byte[4096];
//            int n = 0;
//            while (-1 != (n = is.read(buffer))) {
//                os.write(buffer, 0, n);
//            }
//
//            byte[] bytes = os.toByteArray();
//
//            JsonKeyEntry entry = getGson().fromJson(new String(bytes, Charset.forName("UTF-8")),
//                    JsonKeyEntry.class);
//            entry.setName(keyName);
//
//            return entry;
//        } catch (Exception e) {
//            throw new KeyStorageException(e);
//        }
//    }
//
//    @Override
//    public Set<String> names() {
//        File dir = new File(keysPath);
//        Set<String> names = new HashSet<>();
//        if (dir.exists() && dir.isDirectory()) {
//            for (File file : dir.listFiles()) {
//                names.add(file.getName());
//            }
//        }
//        return names;
//    }
//
//    @Override
//    public void store(KeyEntry keyEntry) {
//        File dir = new File(keysPath);
//
//        if (dir.exists()) {
//            if (!dir.isDirectory()) {
//                throw new InvalidPathException(keysPath, "Is not a directory");
//            }
//        } else {
//            dir.mkdirs();
//        }
//
//        String name = keyEntry.getName();
//        if (exists(name)) {
//            throw new KeyEntryAlreadyExistsException();
//        }
//
//        KeyEntry entry;
//        if (keyEntry instanceof JsonKeyEntry) {
//            entry = keyEntry;
//        } else {
//            entry = new JsonKeyEntry(keyEntry.getName(), keyEntry.getValue());
//            entry.setMeta(keyEntry.getMeta());
//        }
//
//        String json = getGson().toJson(entry);
//        File file = new File(dir, name.toLowerCase());
//        try (FileOutputStream os = new FileOutputStream(file)) {
//            os.write(json.getBytes(Charset.forName("UTF-8")));
//        } catch (Exception e) {
//            throw new KeyStorageException(e);
//        }
//    }
//
//    private Gson getGson() {
//        GsonBuilder builder = new GsonBuilder();
//        Gson gson = builder.create();
//
//        return gson;
//    }
//
//    @Override
//    public KeyEntry createEntry(String name, byte[] value) {
//        return new JsonKeyEntry(name, value);
//    }
//
//    @Override
//    public void update(final KeyEntry keyEntry) {
//        encryptPerformDecrypt(new EncryptedOperation() {
//            @Override
//            public void perform() {
//                String keyName = keyEntry.getName();
//                if (!exists(keyName)) {
//                    throw new KeyEntryNotFoundException();
//                }
//                delete(keyName);
//                store(keyEntry);
//            }
//        });
//    }
//
//    /**
//     * Decrypts storage then performs provided operation, after that encrypts storage again.
//     *
//     * @param operation To perform on decrypt
//     */
//    private void encryptPerformDecrypt(EncryptedOperation operation) {
//        SecretKey secretKey = getStorageKey();
//        // get virgil key pair
//        // decrypt virgil private key
//        virgilCrypto.decrypt(keyStorage, virgilPrivateKey);
//        operation.perform();
//        virgilCrypto.encrypt(keyStorage, virgilPublicKey);
//    }
//
//    private interface EncryptedOperation {
//
//        void perform();
//    }
//}
