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
package com.virgilsecurity.sdk.highlevel;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.client.model.IdentityType;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.storage.KeyEntry;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilKeyTest {

    private static final String PLAINTEXT = "This is just a text";

    private VirgilApiContext context;
    private VirgilApi virgil;
    private VirgilKey virgilKey;
    private PublicKey publicKey;

    @Before
    public void setUp() {
        context = new VirgilApiContext();
        virgil = new VirgilApiImpl(context);
        virgilKey = virgil.getKeys().generate();
        publicKey = context.getCrypto().importPublicKey(virgilKey.exportPublicKey().getBytes());
    }

    @Test
    public void export() {
        VirgilBuffer exportedKey = virgilKey.export();
        assertNotNull(exportedKey);
    }

    @Test
    public void export_with_password() {
        String pwd = UUID.randomUUID().toString();
        VirgilBuffer exportedKey = virgilKey.export(pwd);
        assertNotNull(exportedKey);
    }

    @Test
    public void sign_buffer() throws CryptoException {
        VirgilBuffer signature = virgilKey.sign(VirgilBuffer.from(PLAINTEXT));
        assertNotNull(signature);

        assertTrue(
                context.getCrypto().verify(VirgilBuffer.from(PLAINTEXT).getBytes(), signature.getBytes(), publicKey));

    }

    @Test
    public void sign_plaintext() throws CryptoException {
        VirgilBuffer signature = virgilKey.sign(PLAINTEXT);
        assertNotNull(signature);

        assertTrue(
                context.getCrypto().verify(VirgilBuffer.from(PLAINTEXT).getBytes(), signature.getBytes(), publicKey));
    }

    @Test
    public void sign_bytes() throws CryptoException {
        VirgilBuffer signature = virgilKey.sign(ConvertionUtils.toBytes(PLAINTEXT));
        assertNotNull(signature);

        assertTrue(
                context.getCrypto().verify(VirgilBuffer.from(PLAINTEXT).getBytes(), signature.getBytes(), publicKey));
    }

    @Test
    public void decrypt_buffer() throws CryptoException {
        byte[] encrypted = context.getCrypto().encrypt(ConvertionUtils.toBytes(PLAINTEXT), publicKey);

        VirgilBuffer decrypted = virgilKey.decrypt(VirgilBuffer.from(encrypted));
        assertEquals(PLAINTEXT, decrypted.toString());
    }

    @Test
    public void decrypt_base64String() throws CryptoException {
        byte[] encrypted = context.getCrypto().encrypt(ConvertionUtils.toBytes(PLAINTEXT), publicKey);

        VirgilBuffer decrypted = virgilKey.decrypt(ConvertionUtils.toBase64String(encrypted));
        assertEquals(PLAINTEXT, decrypted.toString());
    }

    @Test
    public void decrypt_bytes() throws CryptoException {
        byte[] encrypted = context.getCrypto().encrypt(ConvertionUtils.toBytes(PLAINTEXT), publicKey);

        VirgilBuffer decrypted = virgilKey.decrypt(encrypted);
        assertEquals(PLAINTEXT, decrypted.toString());
    }

    @Test
    public void signThenEncrypt_buffer() throws CryptoException {
        VirgilKey aliceKey = virgil.getKeys().generate();
        PrivateKey alicePivateKey = context.getCrypto().importPrivateKey(aliceKey.export().getBytes());
        VirgilCard aliceCard = virgil.getCards().createGlobal("alice@virgilsecurity.com", aliceKey, IdentityType.EMAIL);

        VirgilBuffer encrypted = virgilKey.signThenEncrypt(VirgilBuffer.from(PLAINTEXT), Arrays.asList(aliceCard));

        byte[] decrypted = context.getCrypto().decryptThenVerify(encrypted.getBytes(), alicePivateKey, publicKey);
        assertEquals(PLAINTEXT, ConvertionUtils.toString(decrypted));
    }

    @Test
    public void signThenEncrypt_plaintext() throws CryptoException {
        VirgilKey aliceKey = virgil.getKeys().generate();
        PrivateKey alicePivateKey = context.getCrypto().importPrivateKey(aliceKey.export().getBytes());
        VirgilCard aliceCard = virgil.getCards().createGlobal("alice@virgilsecurity.com", aliceKey, IdentityType.EMAIL);

        VirgilBuffer encrypted = virgilKey.signThenEncrypt(PLAINTEXT, Arrays.asList(aliceCard));

        byte[] decrypted = context.getCrypto().decryptThenVerify(encrypted.getBytes(), alicePivateKey, publicKey);
        assertEquals(PLAINTEXT, ConvertionUtils.toString(decrypted));
    }

    @Test
    public void signThenEncrypt_bytes() throws CryptoException {
        VirgilKey aliceKey = virgil.getKeys().generate();
        PrivateKey alicePivateKey = context.getCrypto().importPrivateKey(aliceKey.export().getBytes());
        VirgilCard aliceCard = virgil.getCards().createGlobal("alice@virgilsecurity.com", aliceKey, IdentityType.EMAIL);

        VirgilBuffer encrypted = virgilKey.signThenEncrypt(ConvertionUtils.toBytes(PLAINTEXT),
                Arrays.asList(aliceCard));

        byte[] decrypted = context.getCrypto().decryptThenVerify(encrypted.getBytes(), alicePivateKey, publicKey);
        assertEquals(PLAINTEXT, ConvertionUtils.toString(decrypted));
    }

    @Test
    public void decryptThenVerify_buffer() throws CryptoException {
        VirgilKey aliceKey = virgil.getKeys().generate();
        PrivateKey alicePivateKey = context.getCrypto().importPrivateKey(aliceKey.export().getBytes());
        VirgilCard aliceCard = virgil.getCards().createGlobal("alice@virgilsecurity.com", aliceKey, IdentityType.EMAIL);

        byte[] encrypted = context.getCrypto().signThenEncrypt(ConvertionUtils.toBytes(PLAINTEXT), alicePivateKey,
                publicKey);

        VirgilBuffer decrypted = virgilKey.decryptThenVerify(VirgilBuffer.from(encrypted), aliceCard);

        assertEquals(PLAINTEXT, decrypted.toString());
    }

    @Test
    public void decryptThenVerify_base64String() throws CryptoException {
        VirgilKey aliceKey = virgil.getKeys().generate();
        PrivateKey alicePivateKey = context.getCrypto().importPrivateKey(aliceKey.export().getBytes());
        VirgilCard aliceCard = virgil.getCards().createGlobal("alice@virgilsecurity.com", aliceKey, IdentityType.EMAIL);

        byte[] encrypted = context.getCrypto().signThenEncrypt(ConvertionUtils.toBytes(PLAINTEXT), alicePivateKey,
                publicKey);

        VirgilBuffer decrypted = virgilKey
                .decryptThenVerify(VirgilBuffer.from(encrypted).toString(StringEncoding.Base64), aliceCard);

        assertEquals(PLAINTEXT, decrypted.toString());
    }

    @Test
    public void decryptThenVerify_bytes() throws CryptoException {
        VirgilKey aliceKey = virgil.getKeys().generate();
        PrivateKey alicePivateKey = context.getCrypto().importPrivateKey(aliceKey.export().getBytes());
        VirgilCard aliceCard = virgil.getCards().createGlobal("alice@virgilsecurity.com", aliceKey, IdentityType.EMAIL);

        byte[] encrypted = context.getCrypto().signThenEncrypt(ConvertionUtils.toBytes(PLAINTEXT), alicePivateKey,
                publicKey);

        VirgilBuffer decrypted = virgilKey.decryptThenVerify(encrypted, aliceCard);

        assertEquals(PLAINTEXT, decrypted.toString());
    }

    @Test
    public void save() throws VirgilException {
        String keyName = "key" + new Date().getTime();
        virgilKey.save(keyName);

        KeyEntry keyEntry = context.getKeyStorage().load(keyName);
        assertArrayEquals(virgilKey.export().getBytes(), keyEntry.getValue());
    }

    @Test
    public void save_with_password() throws VirgilException {
        String keyName = "key" + new Date().getTime();
        String pwd = UUID.randomUUID().toString();
        virgilKey.save(keyName, pwd);

        KeyEntry keyEntry = context.getKeyStorage().load(keyName);
        PrivateKey pk = context.getCrypto().importPrivateKey(keyEntry.getValue(), pwd);
        assertArrayEquals(virgilKey.export().getBytes(), pk.getValue());
    }

    @Test
    public void exportPublicKey() {
        byte[] exportedPublicKey = virgilKey.exportPublicKey().getBytes();
        assertArrayEquals(publicKey.getValue(), exportedPublicKey);
    }
}
