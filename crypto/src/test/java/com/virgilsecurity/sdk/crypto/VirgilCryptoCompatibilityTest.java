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

import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.virgilsecurity.crypto.VirgilBase64;
import com.virgilsecurity.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilCryptoCompatibilityTest {

    private VirgilCrypto crypto;
    private JsonObject sampleJson;

    @Before
    public void setup() {
        this.crypto = new VirgilCrypto();

        sampleJson = (JsonObject) new JsonParser().parse(new InputStreamReader(
                this.getClass().getClassLoader().getResourceAsStream("crypto_compatibility_data.json")));
    }
    
    @Test
    public void decryptFromSingleRecipient() throws CryptoException {
        JsonObject json = sampleJson.getAsJsonObject("encrypt_single_recipient");

        byte[] privateKeyData = VirgilBase64.decode(json.get("private_key").getAsString());
        byte[] originalData = VirgilBase64.decode(json.get("original_data").getAsString());
        byte[] cipherData = VirgilBase64.decode(json.get("cipher_data").getAsString());

        VirgilPrivateKey privateKey = this.crypto.importPrivateKey(privateKeyData, null);
        byte[] decryptedData = this.crypto.decrypt(cipherData, privateKey);

        assertArrayEquals(originalData, decryptedData);
    }

    @Test
    public void decryptFromMultipleRecipients() throws CryptoException {
        JsonObject json = sampleJson.getAsJsonObject("encrypt_multiple_recipients");

        List<VirgilPrivateKey> privateKeys = new ArrayList<>();
        for (JsonElement el : json.getAsJsonArray("private_keys")) {
            byte[] privateKeyData = VirgilBase64.decode(el.getAsString());
            privateKeys.add(this.crypto.importPrivateKey(privateKeyData, null));
        }
        byte[] originalData = VirgilBase64.decode(json.get("original_data").getAsString());
        byte[] cipherData = VirgilBase64.decode(json.get("cipher_data").getAsString());

        for (VirgilPrivateKey privateKey : privateKeys) {
            byte[] decryptedData = this.crypto.decrypt(cipherData, privateKey);
            assertArrayEquals(originalData, decryptedData);
        }
    }

    @Test
    public void decryptThenVerifySingleRecipient() throws CryptoException {
        JsonObject json = sampleJson.getAsJsonObject("sign_then_encrypt_single_recipient");

        byte[] privateKeyData = VirgilBase64.decode(json.get("private_key").getAsString());
        byte[] originalData = VirgilBase64.decode(json.get("original_data").getAsString());
        byte[] cipherData = VirgilBase64.decode(json.get("cipher_data").getAsString());

        VirgilPrivateKey privateKey = this.crypto.importPrivateKey(privateKeyData, null);
        byte[] publicKeyData = VirgilKeyPair.extractPublicKey(privateKeyData, new byte[0]);
        VirgilPublicKey publicKey = this.crypto.importPublicKey(publicKeyData);

        byte[] decryptedData = this.crypto.decryptThenVerify(cipherData, privateKey, Arrays.asList(publicKey));
        assertArrayEquals(originalData, decryptedData);
    }

    @Test
    public void decryptThenVerifyMultipleRecipients() throws CryptoException {
        JsonObject json = sampleJson.getAsJsonObject("sign_then_encrypt_multiple_recipients");

        List<VirgilPrivateKey> privateKeys = new ArrayList<>();
        for (JsonElement el : json.getAsJsonArray("private_keys")) {
            byte[] privateKeyData = VirgilBase64.decode(el.getAsString());
            privateKeys.add(this.crypto.importPrivateKey(privateKeyData, null));
        }
        byte[] originalData = VirgilBase64.decode(json.get("original_data").getAsString());
        byte[] cipherData = VirgilBase64.decode(json.get("cipher_data").getAsString());

        byte[] publicKeyData = VirgilKeyPair.extractPublicKey(privateKeys.get(0).getRawKey(), new byte[0]);
        VirgilPublicKey publicKey = this.crypto.importPublicKey(publicKeyData);

        for (VirgilPrivateKey privateKey : privateKeys) {
            byte[] decryptedData = this.crypto.decryptThenVerify(cipherData, privateKey, Arrays.asList(publicKey));
            assertArrayEquals(originalData, decryptedData);
        }
    }
    
    @Test
    public void generateSignature() throws CryptoException {
        JsonObject json = sampleJson.getAsJsonObject("generate_signature");
        
        byte[] privateKeyData = VirgilBase64.decode(json.get("private_key").getAsString());
        byte[] originalData = VirgilBase64.decode(json.get("original_data").getAsString());
        byte[] signature = VirgilBase64.decode(json.get("signature").getAsString());

        VirgilPrivateKey privateKey = this.crypto.importPrivateKey(privateKeyData, null);
        byte[] generatedSignature = this.crypto.generateSignature(originalData, privateKey);
        
        assertArrayEquals(signature, generatedSignature);
    }
    
    @Test
    public void decryptThenVerifyMultipleSigners() throws CryptoException {
        JsonObject json = sampleJson.getAsJsonObject("sign_then_encrypt_multiple_signers");
        
        byte[] privateKeyData = VirgilBase64.decode(json.get("private_key").getAsString());
        byte[] originalData = VirgilBase64.decode(json.get("original_data").getAsString());
        byte[] cipherData = VirgilBase64.decode(json.get("cipher_data").getAsString());
        List<VirgilPublicKey> publicKeys = new ArrayList<>();
        for (JsonElement el : json.getAsJsonArray("public_keys")) {
            byte[] publicKeyData = VirgilBase64.decode(el.getAsString());
            publicKeys.add(this.crypto.importPublicKey(publicKeyData));
        }

        VirgilPrivateKey privateKey = this.crypto.importPrivateKey(privateKeyData, null);
        
        byte[] decryptedData = this.crypto.decryptThenVerify(cipherData, privateKey, publicKeys);
        assertArrayEquals(originalData, decryptedData);
    }

}
