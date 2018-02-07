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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.virgilsecurity.crypto.VirgilHash;
import com.virgilsecurity.crypto.VirgilHash.Algorithm;
import com.virgilsecurity.crypto.VirgilSigner;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

/**
 * @author Andrii Iakovenko
 *
 */
public class CryptoFormatsTests {

    private VirgilCrypto crypto;
    private JsonObject sampleJson;

    @Before
    public void setup() {
        this.crypto = new VirgilCrypto();
        sampleJson = (JsonObject) new JsonParser().parse(new InputStreamReader(this.getClass().getClassLoader()
                .getResourceAsStream("com/virgilsecurity/sdk/crypto/crypto_formats_data.json")));
    }

    @Test
    public void STC_30() throws CryptoException {
        byte[] data = sampleJson.get("STC-30").getAsString().getBytes(StandardCharsets.UTF_8);
        VirgilKeyPair keyPair = this.crypto.generateKeys();

        // Sign with Virgil Crypto
        byte[] signature = this.crypto.generateSignature(data, keyPair.getPrivateKey());
        assertNotNull(signature);

        // Sign with Crypto
        try (VirgilSigner signer = new VirgilSigner(VirgilHash.Algorithm.SHA512)) {
            byte[] signature2 = signer.sign(data, keyPair.getPrivateKey().getRawKey());
            assertArrayEquals(signature2, signature);
        }
    }

    @Test
    public void STC_31_generateKeys() throws CryptoException {
        // Generate keypair
        VirgilKeyPair keyPair = this.crypto.generateKeys();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublicKey());
        assertNotNull(keyPair.getPrivateKey());

        // Export key
        byte[] exportedPrivateKey = this.crypto.exportPrivateKey(keyPair.getPrivateKey(), null);
        assertNotNull(exportedPrivateKey);

        byte[] exportedPrivateKeyWithPassword = this.crypto.exportPrivateKey(keyPair.getPrivateKey(), "qwerty");
        assertNotNull(exportedPrivateKeyWithPassword);

        byte[] exportedPublicKey = this.crypto.exportPublicKey(keyPair.getPublicKey());
        assertNotNull(exportedPublicKey);
    }

    @Test
    @Ignore
    public void STC_31_generateMultipleKeys() throws CryptoException {
        // generate multiple key pairs
        for (KeysType keyType : KeysType.values()) {
            try {
                VirgilKeyPair keyPair = this.crypto.generateKeys(keyType);
                assertNotNull(keyPair);
                assertNotNull(keyPair.getPublicKey());
                assertNotNull(keyPair.getPrivateKey());

                // Export key
                byte[] exportedPrivateKey = this.crypto.exportPrivateKey(keyPair.getPrivateKey(), null);
                assertNotNull(exportedPrivateKey);

                byte[] exportedPrivateKeyWithPassword = this.crypto.exportPrivateKey(keyPair.getPrivateKey(), "qwerty");
                assertNotNull(exportedPrivateKeyWithPassword);

                byte[] exportedPublicKey = this.crypto.exportPublicKey(keyPair.getPublicKey());
                assertNotNull(exportedPublicKey);
            } catch (Exception e) {
                fail("Failed test for key: " + keyType + ": " + e.getMessage());
            }
        }
    }

    @Test
    public void STC_31_importPrivateKey() throws CryptoException {
        JsonObject json = sampleJson.getAsJsonObject("STC-31");
        byte[] keyData = DatatypeConverter.parseBase64Binary(json.get("private_key1").getAsString());
        PrivateKey privateKey = this.crypto.importPrivateKey(keyData);
        assertNotNull(privateKey);

        byte[] exportedPrivateKey = this.crypto.exportPrivateKey((VirgilPrivateKey) privateKey, null);
        assertNotNull(exportedPrivateKey);
    }

    @Test
    public void STC_31_importPrivateKeyWithPassword() throws CryptoException {
        JsonObject json = sampleJson.getAsJsonObject("STC-31");
        byte[] keyData = DatatypeConverter.parseBase64Binary(json.get("private_key2").getAsString());
        String password = json.get("private_key2_password").getAsString();
        PrivateKey privateKey = this.crypto.importPrivateKey(keyData, password);
        assertNotNull(privateKey);

        byte[] exportedPrivateKey = this.crypto.exportPrivateKey((VirgilPrivateKey) privateKey, password);
        assertNotNull(exportedPrivateKey);
    }

    @Test
    public void STC_32() throws CryptoException {
        byte[] keyData = DatatypeConverter.parseBase64Binary(sampleJson.get("STC-32").getAsString());
        PublicKey publicKey = this.crypto.importPublicKey(keyData);
        assertNotNull(publicKey);

        byte[] exportedPublicKey = this.crypto.exportPublicKey((VirgilPublicKey) publicKey);
        assertNotNull(exportedPublicKey);
    }

    @Test
    public void STC_33_sha512() throws CryptoException {
        VirgilKeyPair keyPair = this.crypto.generateKeys();
        VirgilPublicKey publicKey = keyPair.getPublicKey();

        try (VirgilHash hasher = new VirgilHash(Algorithm.SHA512)) {
            byte[] hash = hasher.hash(publicKey.getRawKey());
            byte[] id = Arrays.copyOf(hash, 8);

            assertArrayEquals(id, publicKey.getIdentifier());
        }
    }

    @Test
    public void STC_33_sha256() throws CryptoException {
        this.crypto.setUseSHA256Fingerprints(true);

        VirgilKeyPair keyPair = this.crypto.generateKeys();
        VirgilPublicKey publicKey = keyPair.getPublicKey();

        try (VirgilHash hasher = new VirgilHash(Algorithm.SHA256)) {
            byte[] id = hasher.hash(publicKey.getRawKey());

            assertArrayEquals(id, publicKey.getIdentifier());
        }
    }

}
