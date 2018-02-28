/*******************************************************************************
 * Copyright (c) 2015-2018, Virgil Security, Inc.
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
 *******************************************************************************/
package com.virgilsecurity.sdk.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.virgilsecurity.crypto.VirgilHash;
import com.virgilsecurity.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.EncryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.SigningException;
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.exception.NullArgumentException;

/**
 * Unit tests for {@link VirgilCrypto}
 *
 * @author Andrii Iakovenko
 *
 */
@RunWith(Parameterized.class)
public class VirgilCryptoTest {

    private static final String TEXT = "This text is used for unit tests";
    private static final String PASSWORD = "ThisIsPassWoRd2016";
    private static final byte[] INVALID_SIGNATURE = new byte[] { 48, 88, 48, 13, 6, 9, 96, -122, 72, 1, 101, 3, 4, 2, 2,
            5, 0, 4, 71, 48, 69, 2, 33, 0, -108, -6, -82, 29, -38, 103, -13, 42, 101, 76, -34, -53, -96, -70, 85, 80, 0,
            88, 77, 48, 9, -100, 81, 39, -51, -125, -102, -107, -108, 14, -88, 7, 2, 32, 13, -71, -99, 8, -69, -77, 30,
            98, 20, -25, 60, 125, -19, 67, 12, -30, 65, 93, -29, -92, -58, -91, 91, 50, -111, -79, 50, -123, -39, 36,
            48, -20 };

    private KeysType keysType;
    private Crypto crypto;

    @Parameters(name = "keyType={0}")
    public static KeysType[] params() {
        Set<KeysType> values = new HashSet<>(Arrays.asList(KeysType.values()));
        // Skip RSA test because they are too slow
//        values.remove(KeysType.RSA_3072);
        values.remove(KeysType.RSA_4096);
        values.remove(KeysType.RSA_8192);
        return values.toArray(new KeysType[0]);
    }

    /**
     * Create new instance of {@link VirgilCryptoTest}.
     */
    public VirgilCryptoTest(KeysType keysType) {
        this.keysType = keysType;
    }

    @Before
    public void setUp() {
        crypto = new VirgilCrypto();
    }

    @Test
    public void createVirgilHash() {
        for (HashAlgorithm algorithm : HashAlgorithm.values()) {
            VirgilHash hash = VirgilCrypto.createVirgilHash(algorithm);
            assertNotNull(hash);
        }
    }

    @Test
    public void toVirgilKeyPairType() {
        for (KeysType keysType : KeysType.values()) {
            VirgilKeyPair.Type type = VirgilCrypto.toVirgilKeyPairType(keysType);
            assertNotNull(type);
        }
    }

    @Test(expected = NullArgumentException.class)
    public void calculateFingerprint_null() {
        crypto.calculateFingerprint(null);
    }

    @Test
    public void calculateFingerprint() {
        Fingerprint fingerprint = crypto.calculateFingerprint(TEXT.getBytes());
        assertNotNull(fingerprint);
        assertNotNull(fingerprint.getValue());
        assertTrue(fingerprint.getValue().length > 0);
    }

    @Test(expected = NullArgumentException.class)
    public void computeHash_nullData() {
        crypto.computeHash(null, HashAlgorithm.MD5);
    }

    @Test(expected = NullArgumentException.class)
    public void computeHash() {
        for (HashAlgorithm algorithm : HashAlgorithm.values()) {
            byte[] hash = crypto.computeHash(null, algorithm);

            assertNotNull(hash);
            assertTrue(hash.length > 0);
        }
    }

    @Test
    public void decrypt() throws VirgilException {
        List<PrivateKey> privateKeys = new ArrayList<>();
        List<PublicKey> recipients = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            KeyPair keyPair = crypto.generateKeys();
            privateKeys.add(keyPair.getPrivateKey());
            recipients.add(keyPair.getPublicKey());
        }
        byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients.toArray(new PublicKey[0]));
        for (PrivateKey privateKey : privateKeys) {
            byte[] decrypted = crypto.decrypt(encrypted, privateKey);
            assertArrayEquals(TEXT.getBytes(), decrypted);
        }
    }

    @Test
    public void decrypt_stream() throws IOException, VirgilException {
        List<PrivateKey> privateKeys = new ArrayList<>();
        List<PublicKey> recipients = new ArrayList<>();
        for (int i = 0; i < 1; i++) {
            KeyPair keyPair = crypto.generateKeys();
            privateKeys.add(keyPair.getPrivateKey());
            recipients.add(keyPair.getPublicKey());
        }
        byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients.toArray(new PublicKey[0]));
        try (InputStream is = new ByteArrayInputStream(encrypted);
                ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            for (PrivateKey privateKey : privateKeys) {
                crypto.decrypt(is, os, privateKey);

                byte[] decrypted = os.toByteArray();

                assertArrayEquals(TEXT.getBytes(), decrypted);
            }
        }
    }

    @Test
    public void encrypt() throws VirgilException {
        List<PublicKey> recipients = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            recipients.add(crypto.generateKeys().getPublicKey());
        }
        byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients.toArray(new PublicKey[0]));

        assertNotNull(encrypted);
    }

    @Test
    public void encrypt_noRecipients_success() throws VirgilException {
        byte[] encrypted = crypto.encrypt(TEXT.getBytes(), new PublicKey[0]);

        assertNotNull(encrypted);
    }

    @Test
    public void encrypt_stream() throws IOException, EncryptionException {
        List<PublicKey> recipients = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            recipients.add(crypto.generateKeys().getPublicKey());
        }
        try (OutputStream os = new ByteArrayOutputStream()) {
            crypto.encrypt(new ByteArrayInputStream(TEXT.getBytes()), os, recipients.toArray(new PublicKey[0]));
        }
    }

    @Test
    public void exportPrivateKey() {
        KeyPair keyPair = crypto.generateKeys();
        byte[] key = crypto.exportPrivateKey(keyPair.getPrivateKey());

        assertNotNull(key);
        assertTrue(key.length > 0);
    }

    @Test
    public void exportPrivateKey_withPassword() {
        KeyPair keyPair = crypto.generateKeys();
        byte[] key = crypto.exportPrivateKey(keyPair.getPrivateKey(), PASSWORD);

        assertNotNull(key);
        assertTrue(key.length > 0);
    }

    @Test
    public void exportPublicKey() {
        KeyPair keyPair = crypto.generateKeys();

        byte[] key = crypto.exportPublicKey(keyPair.getPublicKey());

        assertNotNull(key);
        assertTrue(key.length > 0);
    }

    @Test
    public void extractPublicKey() {
        KeyPair keyPair = crypto.generateKeys();

        PublicKey publicKey = crypto.extractPublicKey(keyPair.getPrivateKey());
        assertNotNull(publicKey);
        assertArrayEquals(keyPair.getPublicKey().getId(), publicKey.getId());
        assertArrayEquals(keyPair.getPublicKey().getValue(), publicKey.getValue());
    }

    @Test
    public void generateKeys() {
        KeyPair keyPair = crypto.generateKeys();

        assertNotNull(keyPair);

        PublicKey publicKey = keyPair.getPublicKey();
        assertNotNull(publicKey);
        assertNotNull(publicKey.getId());
        assertNotNull(publicKey.getValue());

        PrivateKey privateKey = keyPair.getPrivateKey();
        assertNotNull(privateKey);
        assertNotNull(privateKey.getId());
        assertNotNull(privateKey.getValue());
    }

    @Test
    public void importPrivateKey() throws CryptoException {
        KeyPair keyPair = crypto.generateKeys();

        byte[] keyData = crypto.exportPrivateKey(keyPair.getPrivateKey());

        PrivateKey importedKey = crypto.importPrivateKey(keyData);

        assertNotNull(importedKey);
        assertNotNull(importedKey.getId());
        assertNotNull(importedKey.getValue());
        assertArrayEquals(keyPair.getPrivateKey().getId(), importedKey.getId());
        assertArrayEquals(keyPair.getPrivateKey().getValue(), importedKey.getValue());
    }

    @Test
    public void importPrivateKey_withPassword() throws CryptoException {
        KeyPair keyPair = crypto.generateKeys();
        byte[] keyData = crypto.exportPrivateKey(keyPair.getPrivateKey(), PASSWORD);

        PrivateKey importedKey = crypto.importPrivateKey(keyData, PASSWORD);

        assertNotNull(importedKey);
        assertNotNull(importedKey.getId());
        assertNotNull(importedKey.getValue());
        assertArrayEquals(keyPair.getPrivateKey().getId(), importedKey.getId());
        assertArrayEquals(keyPair.getPrivateKey().getValue(), importedKey.getValue());
    }

    @Test(expected = CryptoException.class)
    public void importPrivateKey_withWrongPassword() throws CryptoException {
        KeyPair keyPair = crypto.generateKeys();
        byte[] keyData = crypto.exportPrivateKey(keyPair.getPrivateKey(), PASSWORD);

        crypto.importPrivateKey(keyData, PASSWORD + "1");
    }

    @Test
    public void importPublicKey() {
        KeyPair keyPair = crypto.generateKeys();

        byte[] keyData = crypto.exportPublicKey(keyPair.getPublicKey());
        PublicKey publicKey = crypto.importPublicKey(keyData);

        assertNotNull(publicKey);
        assertNotNull(publicKey.getId());
        assertNotNull(publicKey.getValue());
        assertArrayEquals(keyPair.getPublicKey().getId(), publicKey.getId());
        assertArrayEquals(keyPair.getPublicKey().getValue(), publicKey.getValue());
    }

    @Test(expected = NullArgumentException.class)
    public void sign_nullData() {
        KeyPair keyPair = crypto.generateKeys();
        crypto.sign((byte[]) null, keyPair.getPrivateKey());
    }

    @Test(expected = NullArgumentException.class)
    public void sign_nullPrivateKey() {
        crypto.sign(TEXT.getBytes(), null);
    }

    @Test
    public void sign() {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return;
        }
        KeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.sign(TEXT.getBytes(), keyPair.getPrivateKey());

        assertNotNull(signature);
    }

    @Test(expected = NullArgumentException.class)
    public void sign_stream_nullStream() throws SigningException {
        KeyPair keyPair = crypto.generateKeys();
        crypto.sign((InputStream) null, keyPair.getPrivateKey());
    }

    @Test(expected = NullArgumentException.class)
    public void sign_stream_nullPrivateKey() throws SigningException {
        crypto.sign(new ByteArrayInputStream(TEXT.getBytes()), null);
    }

    @Test
    public void sign_stream() throws SigningException {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return;
        }
        KeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.sign(new ByteArrayInputStream(TEXT.getBytes()), keyPair.getPrivateKey());

        assertNotNull(signature);
    }

    @Test
    public void sign_stream_compareToByteArraySign() throws SigningException {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return;
        }
        KeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.sign(TEXT.getBytes(), keyPair.getPrivateKey());
        byte[] streamSignature = crypto.sign(new ByteArrayInputStream(TEXT.getBytes()), keyPair.getPrivateKey());

        assertNotNull(signature);
        assertNotNull(streamSignature);
        assertArrayEquals(signature, streamSignature);
    }

    @Test
    public void verify() throws VerificationException {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return;
        }
        KeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.sign(TEXT.getBytes(), keyPair.getPrivateKey());
        boolean valid = crypto.verify(TEXT.getBytes(), signature, keyPair.getPublicKey());

        assertTrue(valid);
    }

    @Test
    public void verify_invalidSignature() throws VerificationException {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return;
        }
        KeyPair keyPair = crypto.generateKeys();
        crypto.sign(TEXT.getBytes(), keyPair.getPrivateKey());
        boolean valid = crypto.verify(TEXT.getBytes(), INVALID_SIGNATURE, keyPair.getPublicKey());

        assertFalse(valid);
    }

    @Test
    public void verify_stream() throws VerificationException {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return;
        }
        KeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.sign(TEXT.getBytes(), keyPair.getPrivateKey());
        boolean valid = crypto.verify(new ByteArrayInputStream(TEXT.getBytes()), signature, keyPair.getPublicKey());

        assertTrue(valid);
    }

    @Test
    public void verify_stream_invalidSignature() throws VerificationException {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return;
        }
        KeyPair keyPair = crypto.generateKeys();
        crypto.sign(TEXT.getBytes(), keyPair.getPrivateKey());
        boolean valid = crypto.verify(new ByteArrayInputStream(TEXT.getBytes()), INVALID_SIGNATURE,
                keyPair.getPublicKey());

        assertFalse(valid);
    }

}
