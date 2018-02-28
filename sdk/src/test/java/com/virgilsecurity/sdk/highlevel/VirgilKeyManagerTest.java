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

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Date;

import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilKeyManagerTest {

    private KeyManager keyManager;
    private Crypto crypto;
    private String suffix;

    @Before
    public void setUp() {
        keyManager = new VirgilApiImpl().getKeys();
        suffix = String.valueOf(new Date().getTime());
        crypto = new VirgilCrypto();
    }

    @Test
    public void generate() {
        VirgilKey key = keyManager.generate();
        assertNotNull(key);
    }

    @Test
    public void load() throws VirgilException {
        String keyName = "key" + suffix;
        VirgilKey key = keyManager.generate();
        key.save(keyName);

        VirgilKey loadedKey = keyManager.load(keyName);
        assertNotNull(loadedKey);

        assertEquals(key.export().toString(), loadedKey.export().toString());
    }

    @Test
    public void load_with_password() throws VirgilException {
        String keyName = "key" + suffix;
        String pwd = suffix;
        VirgilKey key = keyManager.generate();
        key.save(keyName, pwd);

        VirgilKey loadedKey = keyManager.load(keyName, pwd);
        assertNotNull(loadedKey);

        assertEquals(key.export().toString(), loadedKey.export().toString());
    }

    @Test
    public void load_unprotected_key_with_password() throws VirgilException {
        String keyName = "key" + suffix;
        String pwd = suffix;
        VirgilKey key = keyManager.generate();
        key.save(keyName);

        VirgilKey loadedKey = keyManager.load(keyName, pwd);
        assertNotNull(loadedKey);

        assertEquals(key.export().toString(), loadedKey.export().toString());
    }

    @Test(expected = CryptoException.class)
    public void load_with_wrongPassword() throws VirgilException {
        String keyName = "key" + suffix;
        String pwd = suffix;
        VirgilKey key = keyManager.generate();
        key.save(keyName, pwd);

        keyManager.load(keyName, "1");
    }

    @Test(expected = CryptoException.class)
    public void load_protected_key_withoutPassword() throws VirgilException {
        String keyName = "key" + suffix;
        String pwd = suffix;
        VirgilKey key = keyManager.generate();
        key.save(keyName, pwd);

        keyManager.load(keyName);
    }

    @Test(expected = KeyEntryNotFoundException.class)
    public void load_not_exists() throws VirgilException {
        String keyName = "key" + suffix;
        VirgilKey key = keyManager.generate();
        key.save(keyName);

        keyManager.load("key");
    }

    @Test(expected = KeyEntryNotFoundException.class)
    public void destroy() throws VirgilException {
        String keyName = "key" + suffix;
        VirgilKey key = keyManager.generate();
        key.save(keyName);

        try {
            assertNotNull(keyManager.load(keyName));
        } catch (Exception e) {
            fail();
        }
        keyManager.destroy(keyName);

        keyManager.load(keyName);
    }

    @Test
    public void import_privateKey() {
        KeyPair keyPair = crypto.generateKeys();
        VirgilKey virgilKey = keyManager.importKey(keyPair.getPrivateKey());
        assertNotNull(virgilKey);
        assertThat(virgilKey.getPrivateKey(), is(keyPair.getPrivateKey()));
        assertArrayEquals(keyPair.getPrivateKey().getId(), virgilKey.getPrivateKey().getId());
        assertArrayEquals(keyPair.getPrivateKey().getValue(), virgilKey.getPrivateKey().getValue());
    }

}
