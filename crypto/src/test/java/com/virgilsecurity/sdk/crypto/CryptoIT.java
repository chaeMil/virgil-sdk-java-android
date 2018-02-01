/*
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
 */
package com.virgilsecurity.sdk.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.virgilsecurity.crypto.VirgilBase64;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;

/**
 * Integration tests for Virgil Crypto.
 *
 * @author Andrii Iakovenko
 *
 */
public class CryptoIT {

    private static final String SAMPLE_RESOURCE = "sdk_compatibility_data.json";

    private Crypto crypto;
    private JsonObject sampleJson;

//    @Before
//    public void setUp() throws JsonSyntaxException, IOException {
//        crypto = new VirgilCrypto();
//
//        String sample = IOUtils.toString(this.getClass().getClassLoader().getResourceAsStream(SAMPLE_RESOURCE));
//        JsonParser parser = new JsonParser();
//        sampleJson = (JsonObject) parser.parse(sample);
//    }
//
//    @Test
//    public void encryptSingleRecipient() throws VirgilException {
//        JsonObject data = sampleJson.getAsJsonObject("encrypt_single_recipient");
//        byte[] privateKeyData = VirgilBase64.decode(data.get("private_key").getAsString());
//        byte[] originalData = VirgilBase64.decode(data.get("original_data").getAsString());
//        byte[] cipherData = VirgilBase64.decode(data.get("cipher_data").getAsString());
//
//        PrivateKey privateKey = crypto.importPrivateKey(privateKeyData);
//        PublicKey publicKey = crypto.extractPublicKey(privateKey);
//
//        // Test decryption
//        byte[] decrypted = crypto.decrypt(cipherData, privateKey);
//        assertArrayEquals(originalData, decrypted);
//
//        // Test encryption
//        byte[] encrypted = crypto.encrypt(originalData, publicKey);
//        decrypted = crypto.decrypt(encrypted, privateKey);
//        assertArrayEquals(originalData, decrypted);
//    }
//
//    @Test
//    public void encryptMultipleRecipient() throws VirgilException {
//        JsonObject data = sampleJson.getAsJsonObject("encrypt_multiple_recipients");
//
//        byte[] originalData = VirgilBase64.decode(data.get("original_data").getAsString());
//        byte[] cipherData = VirgilBase64.decode(data.get("cipher_data").getAsString());
//
//        JsonArray privateKeysData = data.getAsJsonArray("private_keys");
//        List<PrivateKey> privateKeys = new ArrayList<>();
//        List<PublicKey> publicKeys = new ArrayList<>();
//
//        for (Iterator<JsonElement> it = privateKeysData.iterator(); it.hasNext();) {
//            byte[] privateKeyData = VirgilBase64.decode(it.next().getAsString());
//
//            PrivateKey privateKey = crypto.importPrivateKey(privateKeyData);
//            PublicKey publicKey = crypto.extractPublicKey(privateKey);
//
//            privateKeys.add(privateKey);
//            publicKeys.add(publicKey);
//        }
//
//        // Test decryption
//        for (PrivateKey privateKey : privateKeys) {
//            byte[] decrypted = crypto.decrypt(cipherData, privateKey);
//            assertArrayEquals(originalData, decrypted);
//        }
//
//        // Test encryption
//        byte[] encrypted = crypto.encrypt(originalData, publicKeys.toArray(new PublicKey[0]));
//
//        for (PrivateKey privateKey : privateKeys) {
//            byte[] decrypted = crypto.decrypt(encrypted, privateKey);
//            assertArrayEquals(originalData, decrypted);
//        }
//    }
//
//    @Test
//    public void signThenEncryptSingleRecipient() throws VirgilException {
//        JsonObject data = sampleJson.getAsJsonObject("sign_then_encrypt_single_recipient");
//        byte[] privateKeyData = VirgilBase64.decode(data.get("private_key").getAsString());
//        byte[] originalData = VirgilBase64.decode(data.get("original_data").getAsString());
//        byte[] cipherData = VirgilBase64.decode(data.get("cipher_data").getAsString());
//
//        PrivateKey privateKey = crypto.importPrivateKey(privateKeyData);
//        PublicKey publicKey = crypto.extractPublicKey(privateKey);
//
//        // Test decryption
//        byte[] decrypted = crypto.decryptThenVerify(cipherData, privateKey, publicKey);
//        assertArrayEquals(originalData, decrypted);
//
//        // Test encryption
//        byte[] encrypted = crypto.signThenEncrypt(originalData, privateKey, publicKey);
//        decrypted = crypto.decryptThenVerify(encrypted, privateKey, publicKey);
//        assertArrayEquals(originalData, decrypted);
//    }
//
//    @Test
//    public void signThenEncryptMultipleRecipients() throws VirgilException {
//        JsonObject data = sampleJson.getAsJsonObject("sign_then_encrypt_multiple_recipients");
//
//        byte[] originalData = VirgilBase64.decode(data.get("original_data").getAsString());
//        byte[] cipherData = VirgilBase64.decode(data.get("cipher_data").getAsString());
//
//        JsonArray privateKeysData = data.getAsJsonArray("private_keys");
//        Map<PrivateKey, PublicKey> keys = new HashMap<>();
//
//        PublicKey sendersKey = null;
//        for (Iterator<JsonElement> it = privateKeysData.iterator(); it.hasNext();) {
//            byte[] privateKeyData = VirgilBase64.decode(it.next().getAsString());
//
//            PrivateKey privateKey = crypto.importPrivateKey(privateKeyData);
//            PublicKey publicKey = crypto.extractPublicKey(privateKey);
//
//            keys.put(privateKey, publicKey);
//
//            if (sendersKey == null) {
//                sendersKey = publicKey;
//            }
//        }
//
//        // Test decryption
//        for (Entry<PrivateKey, PublicKey> entry : keys.entrySet()) {
//            byte[] decrypted = crypto.decryptThenVerify(cipherData, entry.getKey(), sendersKey);
//            assertArrayEquals(originalData, decrypted);
//        }
//
//        // Test encryption
//        for (Entry<PrivateKey, PublicKey> entry : keys.entrySet()) {
//            PrivateKey privateKey = entry.getKey();
//
//            byte[] encrypted = crypto.signThenEncrypt(originalData, privateKey,
//                    keys.values().toArray(new PublicKey[0]));
//            byte[] decrypted = crypto.decryptThenVerify(encrypted, privateKey, entry.getValue());
//            assertArrayEquals(originalData, decrypted);
//        }
//    }
//
//    @Test
//    public void generateSignature() throws VirgilException {
//        JsonObject data = sampleJson.getAsJsonObject("generate_signature");
//        byte[] privateKeyData = VirgilBase64.decode(data.get("private_key").getAsString());
//        byte[] originalData = VirgilBase64.decode(data.get("original_data").getAsString());
//        byte[] signature = VirgilBase64.decode(data.get("signature").getAsString());
//
//        PrivateKey privateKey = crypto.importPrivateKey(privateKeyData);
//        PublicKey publicKey = crypto.extractPublicKey(privateKey);
//
//        // Test signing
//        byte[] sign = crypto.generateSignature(originalData, privateKey);
//        assertArrayEquals(signature, sign);
//
//        // Test verification
//        boolean valid = crypto.verifySignature(originalData, signature, publicKey);
//        assertTrue(valid);
//    }

}
