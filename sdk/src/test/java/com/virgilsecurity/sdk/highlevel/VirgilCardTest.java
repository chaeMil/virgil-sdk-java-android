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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * Unit tests for {@linkplain VirgilCard}.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilCardTest {

    private static final String TEXT = "Let's try to encrypt this text";
    private static final String ALICE_IDENTITY = "alice";

    private VirgilApiContext context;
    private VirgilApi virgil;
    private VirgilKey virgilKey;
    private VirgilCard virgilCard;

    @Before
    public void setUp() {
        context = new VirgilApiContext();
        virgil = new VirgilApiImpl(context);
        virgilKey = virgil.getKeys().generate();
        virgilCard = virgil.getCards().create(ALICE_IDENTITY, virgilKey);
    }

    @Test
    public void encrypt_buffer() throws CryptoException {
        VirgilBuffer cipherData = virgilCard.encrypt(VirgilBuffer.from(TEXT));
        VirgilBuffer decryptedData = virgilKey.decrypt(cipherData);

        assertEquals(TEXT, decryptedData.toString());
    }

    @Test
    public void encrypt_plaintext() throws CryptoException {
        VirgilBuffer cipherData = virgilCard.encrypt(TEXT);
        VirgilBuffer decryptedData = virgilKey.decrypt(cipherData);

        assertEquals(TEXT, decryptedData.toString());
    }

    @Test
    public void encrypt_bytes() throws CryptoException {
        VirgilBuffer cipherData = virgilCard.encrypt(ConvertionUtils.toBytes(TEXT));
        VirgilBuffer decryptedData = virgilKey.decrypt(cipherData);

        assertEquals(TEXT, decryptedData.toString());
    }

    @Test
    public void verify_buffer_buffer() throws CryptoException {
        VirgilBuffer signature = virgilKey.sign(TEXT);

        assertTrue(virgilCard.verify(VirgilBuffer.from(TEXT), signature));
    }

    @Test
    public void verify_string_buffer() throws CryptoException {
        VirgilBuffer signature = virgilKey.sign(TEXT);

        assertTrue(virgilCard.verify(TEXT, signature));
    }

    @Test
    public void verify_string_string() throws CryptoException {
        VirgilBuffer signature = virgilKey.sign(TEXT);

        assertTrue(virgilCard.verify(TEXT, signature.toString(StringEncoding.Base64)));
    }

    @Test
    public void verify_string_bytes() throws CryptoException {
        VirgilBuffer signature = virgilKey.sign(TEXT);

        assertTrue(virgilCard.verify(TEXT, signature.getBytes()));
    }

}
