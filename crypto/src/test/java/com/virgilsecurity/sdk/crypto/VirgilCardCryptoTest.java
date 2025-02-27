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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import com.virgilsecurity.crypto.foundation.Base64;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import java.nio.charset.StandardCharsets;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for {@link VirgilCardCrypto}.
 * 
 * @author Andrii Iakovenko
 *
 */
public class VirgilCardCryptoTest {

  private static final String TEST_TEXT = "Lorem Ipsum is simply dummy text.";
  private static final byte[] TEST_DATA = TEST_TEXT.getBytes(StandardCharsets.UTF_8);

  private VirgilCardCrypto cardCrypto;
  private PublicKey publicKey;
  private PrivateKey privateKey;

  @Test
  public void exportPublicKey() throws CryptoException {
    byte[] keyData = this.cardCrypto.exportPublicKey(this.publicKey);
    assertNotNull(keyData);
  }

  @Test(expected = NullArgumentException.class)
  public void exportPublicKey_null() throws CryptoException {
    this.cardCrypto.exportPublicKey(null);
  }

  @Test(expected = CryptoException.class)
  public void exportPublicKey_wrongKey() throws CryptoException {
    PublicKey key = new PublicKey() {
    };
    this.cardCrypto.exportPublicKey(key);
  }

  @Test
  public void generateSha512() throws CryptoException {
    byte[] hash = this.cardCrypto.computeSha512(TEST_DATA);
    assertNotNull(hash);
    assertArrayEquals(
        Base64.decode(
            "sjkkPe4LyXDsOl7R9K57Zeu4X3beeV9JmwOvaBUFLMWKeKeMkv25r3YhPS/mQF6d2TWjNGGMxQnH9szJolYZGg=="
                .getBytes()),
        hash);
  }

  @Test(expected = NullArgumentException.class)
  public void generateSha512_null() throws CryptoException {
    this.cardCrypto.computeSha512(null);
  }

  @Test
  public void generateSignature() throws CryptoException {
    byte[] signature = this.cardCrypto.generateSignature(TEST_DATA, this.privateKey);

    assertNotNull(signature);
  }

  @Test(expected = NullArgumentException.class)
  public void generateSignature_nullData() throws CryptoException {
    this.cardCrypto.generateSignature(null, this.privateKey);
  }

  @Test(expected = NullArgumentException.class)
  public void generateSignature_nullKey() throws CryptoException {
    this.cardCrypto.generateSignature(TEST_DATA, null);
  }

  @Test(expected = CryptoException.class)
  public void generateSignature_wrongKey() throws CryptoException {
    PrivateKey key = new PrivateKey() {
    };
    this.cardCrypto.generateSignature(TEST_DATA, key);
  }

  @Test
  public void getVirgilCrypto() {
    VirgilCrypto crypto = this.cardCrypto.getVirgilCrypto();
    assertNotNull(crypto);
  }

  @Test
  public void importPublicKey() throws CryptoException {
    byte[] exportedKeyData = this.cardCrypto.exportPublicKey(this.publicKey);
    PublicKey importedPublicKey = this.cardCrypto.importPublicKey(exportedKeyData);

    assertNotNull(importedPublicKey);
    assertThat(importedPublicKey, instanceOf(VirgilPublicKey.class));
  }

  @Test(expected = NullArgumentException.class)
  public void importPublicKey_null() throws CryptoException {
    this.cardCrypto.importPublicKey(null);
  }

  @Test(expected = CryptoException.class)
  public void importPublicKey_wrongData() throws CryptoException {
    this.cardCrypto.importPublicKey(TEST_DATA);
  }

  @Before
  public void setup() throws CryptoException {
    this.cardCrypto = new VirgilCardCrypto();

    VirgilKeyPair keyPair = this.cardCrypto.getVirgilCrypto().generateKeyPair();
    this.privateKey = keyPair.getPrivateKey();
    this.publicKey = keyPair.getPublicKey();
  }

  @Test
  public void verifySignature() throws CryptoException {
    byte[] signature = this.cardCrypto.generateSignature(TEST_DATA, this.privateKey);
    assertTrue(this.cardCrypto.verifySignature(signature, TEST_DATA, this.publicKey));
  }

  @Test
  public void verifySignature_invalidSignature() throws CryptoException {
    byte[] signature = this.cardCrypto.generateSignature(TEST_DATA, this.privateKey);
    assertFalse(
        this.cardCrypto.verifySignature(signature, (TEST_TEXT + " ").getBytes(), this.publicKey));
  }

  @Test(expected = NullArgumentException.class)
  public void verifySignature_nullData() throws CryptoException {
    byte[] signature = this.cardCrypto.generateSignature(TEST_DATA, this.privateKey);
    this.cardCrypto.verifySignature(signature, null, this.publicKey);
  }

  @Test(expected = NullArgumentException.class)
  public void verifySignature_nullKey() throws CryptoException {
    byte[] signature = this.cardCrypto.generateSignature(TEST_DATA, this.privateKey);
    this.cardCrypto.verifySignature(signature, TEST_DATA, null);
  }

  @Test(expected = NullArgumentException.class)
  public void verifySignature_nullSignature() throws CryptoException {
    this.cardCrypto.verifySignature(null, TEST_DATA, this.publicKey);
  }
}
