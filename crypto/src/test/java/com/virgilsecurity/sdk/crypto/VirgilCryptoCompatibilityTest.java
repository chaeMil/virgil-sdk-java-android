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

package com.virgilsecurity.sdk.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.virgilsecurity.crypto.foundation.Base64;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * Unit tests for {@link VirgilCrypto} which tests cross-platform compatibility.
 * 
 * @author Andrii Iakovenko
 *
 */
@RunWith(Parameterized.class)
public class VirgilCryptoCompatibilityTest {

  private VirgilCrypto crypto;
  private JsonObject sampleJson;

  @Before
  public void setup() {
    this.crypto = new VirgilCrypto();
    this.crypto.setUseSHA256Fingerprints(true);

    sampleJson = (JsonObject) new JsonParser()
        .parse(new InputStreamReader(Objects.requireNonNull(
            this.getClass().getClassLoader()
                .getResourceAsStream(
                    "com/virgilsecurity/sdk/crypto/crypto_compatibility_data.json"))));
  }

  @Parameters
  public static Collection<VirgilCrypto> cryptos() {
    List<VirgilCrypto> cryptos = new ArrayList<>();

    cryptos.add(new VirgilCrypto(true));

    VirgilCrypto crypto = new VirgilCrypto();
    crypto.setUseSHA256Fingerprints(true);
    cryptos.add(crypto);

    return cryptos;
  }

  /**
   * Create new instance of {@link VirgilCryptoCompatibilityTest}.
   */
  public VirgilCryptoCompatibilityTest(VirgilCrypto crypto) {
    this.crypto = crypto;
  }

  @Test
  public void decryptFromMultipleRecipients() throws CryptoException {
    JsonObject json = sampleJson.getAsJsonObject("encrypt_multiple_recipients");

    List<VirgilPrivateKey> privateKeys = new ArrayList<>();
    for (JsonElement el : json.getAsJsonArray("private_keys")) {
      byte[] privateKeyData = Base64.decode(el.getAsString().getBytes());
      privateKeys.add(this.crypto.importPrivateKey(privateKeyData).getPrivateKey());
    }
    byte[] originalData = Base64.decode(json.get("original_data").getAsString().getBytes());
    byte[] cipherData = Base64.decode(json.get("cipher_data").getAsString().getBytes());

    for (VirgilPrivateKey privateKey : privateKeys) {
      byte[] decryptedData = this.crypto.decrypt(cipherData, privateKey);
      assertArrayEquals(originalData, decryptedData);
    }
  }

  @Test
  public void decryptFromSingleRecipient() throws CryptoException {
    JsonObject json = sampleJson.getAsJsonObject("encrypt_single_recipient");

    byte[] privateKeyData = Base64.decode(json.get("private_key").getAsString().getBytes());
    byte[] originalData = Base64.decode(json.get("original_data").getAsString().getBytes());
    byte[] cipherData = Base64.decode(json.get("cipher_data").getAsString().getBytes());

    VirgilPrivateKey privateKey = this.crypto.importPrivateKey(privateKeyData).getPrivateKey();
    byte[] decryptedData = this.crypto.decrypt(cipherData, privateKey);

    assertArrayEquals(originalData, decryptedData);
  }

  @Test
  public void decryptThenVerifyMultipleRecipients() throws CryptoException {
    JsonObject json = sampleJson.getAsJsonObject("sign_then_encrypt_multiple_recipients");

    List<VirgilKeyPair> keyPairs = new ArrayList<>();
    for (JsonElement el : json.getAsJsonArray("private_keys")) {
      byte[] privateKeyData = Base64.decode(el.getAsString().getBytes());
      keyPairs.add(this.crypto.importPrivateKey(privateKeyData));
    }
    byte[] originalData = Base64.decode(json.get("original_data").getAsString().getBytes());
    byte[] cipherData = Base64.decode(json.get("cipher_data").getAsString().getBytes());

    byte[] publicKeyData = keyPairs.get(0).getPublicKey().getPublicKey().exportPublicKey();
    VirgilPublicKey publicKey = this.crypto.importPublicKey(publicKeyData);

    for (VirgilKeyPair keyPair : keyPairs) {
      byte[] decryptedData = this.crypto.decryptThenVerify(cipherData, keyPair.getPrivateKey(),
                                                           Collections.singletonList(publicKey));
      assertArrayEquals(originalData, decryptedData);
    }
  }

  @Test
  public void decryptThenVerifyMultipleSigners() throws CryptoException {
    JsonObject json = sampleJson.getAsJsonObject("sign_then_encrypt_multiple_signers");

    byte[] privateKeyData = Base64.decode(json.get("private_key").getAsString().getBytes());
    byte[] originalData = Base64.decode(json.get("original_data").getAsString().getBytes());
    byte[] cipherData = Base64.decode(json.get("cipher_data").getAsString().getBytes());
    List<VirgilPublicKey> publicKeys = new ArrayList<>();
    for (JsonElement el : json.getAsJsonArray("public_keys")) {
      byte[] publicKeyData = Base64.decode(el.getAsString().getBytes());
      publicKeys.add(this.crypto.importPublicKey(publicKeyData));
    }

    VirgilPrivateKey privateKey = this.crypto.importPrivateKey(privateKeyData).getPrivateKey();

    byte[] decryptedData = this.crypto.decryptThenVerify(cipherData, privateKey, publicKeys);
    assertArrayEquals(originalData, decryptedData);
  }

  @Test
  public void decryptThenVerifySingleRecipient() throws CryptoException {
    JsonObject json = sampleJson.getAsJsonObject("sign_then_encrypt_single_recipient");

    byte[] privateKeyData = Base64.decode(json.get("private_key").getAsString().getBytes());
    byte[] originalData = Base64.decode(json.get("original_data").getAsString().getBytes());
    byte[] cipherData = Base64.decode(json.get("cipher_data").getAsString().getBytes());

    VirgilKeyPair keyPair = this.crypto.importPrivateKey(privateKeyData);
    VirgilPublicKey publicKey = keyPair.getPublicKey();

    byte[] decryptedData = this.crypto.decryptThenVerify(cipherData, keyPair.getPrivateKey(),
                                                         Collections.singletonList(publicKey));
    assertArrayEquals(originalData, decryptedData);
  }

  @Test
  public void generateSignature() throws CryptoException {
    JsonObject json = sampleJson.getAsJsonObject("generate_signature");

    byte[] privateKeyData = Base64.decode(json.get("private_key").getAsString().getBytes());
    byte[] originalData = Base64.decode(json.get("original_data").getAsString().getBytes());
    byte[] signature = Base64.decode(json.get("signature").getAsString().getBytes());

    VirgilKeyPair keyPair = this.crypto.importPrivateKey(privateKeyData);
    byte[] generatedSignature = this.crypto.generateSignature(originalData,
                                                              keyPair.getPrivateKey());

    assertArrayEquals(signature, generatedSignature);

    VirgilPublicKey publicKey = keyPair.getPublicKey();
    assertTrue(this.crypto.verifySignature(signature, originalData, publicKey));
  }
}
