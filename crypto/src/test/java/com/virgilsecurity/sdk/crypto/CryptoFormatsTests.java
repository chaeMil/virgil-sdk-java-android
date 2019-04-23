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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.virgilsecurity.crypto.foundation.Hash;
import com.virgilsecurity.crypto.foundation.Pkcs8Serializer;
import com.virgilsecurity.crypto.foundation.Sha256;
import com.virgilsecurity.crypto.foundation.Sha512;
import com.virgilsecurity.crypto.foundation.SignHash;
import com.virgilsecurity.crypto.foundation.Signer;
import com.virgilsecurity.crypto.utils.Base64;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

/**
 * Unit tests which verify cross-platform compatibility.
 *
 * @author Andrii Iakovenko
 *
 */
public class CryptoFormatsTests {

  private VirgilCrypto crypto;
  private JsonObject sampleJson;

  @Before
  public void setup() {
    this.crypto = new VirgilCrypto();
    sampleJson = (JsonObject) new JsonParser()
        .parse(new InputStreamReader(
            Objects.requireNonNull(
                this.getClass().getClassLoader().getResourceAsStream(
                    "com/virgilsecurity/sdk/crypto/crypto_formats_data.json"))));
  }

  @Test
  public void stc_30() throws CryptoException {
    // STC_30
    byte[] data = sampleJson.get("STC-30").getAsString().getBytes(StandardCharsets.UTF_8);
    VirgilKeyPair keyPair = this.crypto.generateKeyPair();

    // Sign with Virgil Crypto
    byte[] signature = this.crypto.generateSignature(data, keyPair.getPrivateKey());
    assertNotNull(signature);

    // Sign with Crypto
    try (Signer signer = new Signer()) {
      signer.setHash(new Sha512());

      signer.reset();
      signer.update(data);

      SignHash signHash = (SignHash) keyPair.getPrivateKey().getPrivateKey();
      byte[] signature2 = signer.sign(signHash);

      assertArrayEquals(signature2, signature);
    }
  }

  @Test
  public void stc_31_generateKeys() throws CryptoException {
    // STC_31
    // Generate keypair
    VirgilKeyPair keyPair = this.crypto.generateKeyPair();
    assertNotNull(keyPair);
    assertNotNull(keyPair.getPublicKey());
    assertNotNull(keyPair.getPrivateKey());

    // Export key
    byte[] exportedPrivateKey = this.crypto.exportPrivateKey(keyPair.getPrivateKey());
    assertNotNull(exportedPrivateKey);

    byte[] exportedPrivateKeyWithPassword = this.crypto.exportPrivateKey(keyPair.getPrivateKey());
    assertNotNull(exportedPrivateKeyWithPassword);

    byte[] exportedPublicKey = this.crypto.exportPublicKey(keyPair.getPublicKey());
    assertNotNull(exportedPublicKey);
  }

  @Test
  @Ignore
  public void stc_31_generateMultipleKeys() {
    // STC_31
    // generate multiple key pairs
    for (KeyType keyType : KeyType.values()) {
      try {
        VirgilKeyPair keyPair = this.crypto.generateKeyPair(keyType);
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublicKey());
        assertNotNull(keyPair.getPrivateKey());

        // Export key
        byte[] exportedPrivateKey = this.crypto.exportPrivateKey(keyPair.getPrivateKey());
        assertNotNull(exportedPrivateKey);

        byte[] exportedPrivateKeyWithPassword = this.crypto
            .exportPrivateKey(keyPair.getPrivateKey());
        assertNotNull(exportedPrivateKeyWithPassword);

        byte[] exportedPublicKey = this.crypto.exportPublicKey(keyPair.getPublicKey());
        assertNotNull(exportedPublicKey);
      } catch (Exception e) {
        fail("Failed test for key: " + keyType + ": " + e.getMessage());
      }
    }
  }

  @Test
  public void stc_31_importPrivateKey() throws CryptoException {
    // STC_31
    JsonObject json = sampleJson.getAsJsonObject("STC-31");
    byte[] keyData = Base64.decode(json.get("private_key1").getAsString());
    VirgilKeyPair keyPair = this.crypto.importPrivateKey(keyData);
    assertNotNull(keyPair.getPrivateKey());

    byte[] exportedPrivateKey = this.crypto.exportPrivateKey(keyPair.getPrivateKey());
    assertNotNull(exportedPrivateKey);
  }

  @Test
  public void stc_32() throws CryptoException {
    // STC_32
    byte[] keyData = Base64.decode(sampleJson.get("STC-32").getAsString());
    VirgilPublicKey publicKey = this.crypto.importPublicKey(keyData);
    assertNotNull(publicKey);

    byte[] exportedPublicKey = this.crypto.exportPublicKey(publicKey);
    assertNotNull(exportedPublicKey);
  }

  @Test
  public void stc_33_sha256() throws CryptoException {
    // STC_33
    this.crypto.setUseSHA256Fingerprints(true);

    VirgilKeyPair keyPair = this.crypto.generateKeyPair();

    Pkcs8Serializer serializer = new Pkcs8Serializer();
    serializer.setupDefaults();

    byte[] publicKeyDer = serializer.serializePublicKey(keyPair.getPublicKey().getPublicKey());

    Hash hash = new Sha256();
    byte[] id = hash.hash(publicKeyDer);

    assertArrayEquals(id, keyPair.getPublicKey().getIdentifier());
  }

  @Test
  public void stc_33_sha512() throws CryptoException {
    // STC_33
    VirgilKeyPair keyPair = this.crypto.generateKeyPair();
    Pkcs8Serializer serializer = new Pkcs8Serializer();
    serializer.setupDefaults();

    byte[] publicKeyDer = serializer.serializePublicKey(keyPair.getPublicKey().getPublicKey());

    Hash hasher = new Sha512();
    byte[] hash = hasher.hash(publicKeyDer);
    byte[] id = Arrays.copyOf(hash, 8);

    assertArrayEquals(id, keyPair.getPublicKey().getIdentifier());
  }

}
