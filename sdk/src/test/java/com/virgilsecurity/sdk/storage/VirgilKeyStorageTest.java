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
package com.virgilsecurity.sdk.storage;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

import com.virgilsecurity.crypto.VirgilKeyPair;
import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryAlreadyExistsException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;

/**
 * Unit tests for {@code VirgilKeyStorage}
 *
 * @author Andrii Iakovenko
 * 
 * @see VirgilKeyStorage
 *
 */
public class VirgilKeyStorageTest {
    private VirgilCrypto crypto;
    private VirgilKeyStorage storage;

    private File tmpDir;
    private String alias;
    private KeyEntry entry;

    private VirgilKeyPair keyPair;

    @Before
    public void setUp() {
//        crypto = new VirgilCrypto();
//
//        tmpDir = new File(System.getProperty("java.io.tmpdir") + File.separator + UUID.randomUUID().toString());
//        storage = new VirgilKeyStorage(tmpDir.getAbsolutePath());
//
//        keyPair = crypto.generateKeys();
//
//        alias = UUID.randomUUID().toString();
//
//        entry = new VirgilKeyEntry();
//        entry.setName(alias);
//        entry.setValue(crypto.exportPrivateKey(keyPair.getPrivateKey()));
//        entry.getMetadata().put(UUID.randomUUID().toString(), UUID.randomUUID().toString());
    }

    @Test
    public void exists_nullAlias() {
        assertFalse(storage.exists(null));
    }

    @Test
    public void exists_randomName() {
        assertFalse(storage.exists(UUID.randomUUID().toString()));
    }

    @Test
    public void exists() throws IOException {
        if (!tmpDir.exists()) {
            tmpDir.mkdirs();
        }
        File tmpFile = File.createTempFile(alias, "", tmpDir);
        String name = tmpFile.getName();

        assertTrue(storage.exists(name));
    }

    @Test
    public void store() {
        storage.store(entry);

        assertTrue(storage.exists(alias));
    }

    @Test(expected = KeyEntryAlreadyExistsException.class)
    public void store_duplicated() {
        storage.store(entry);
        storage.store(entry);
    }

    @Test
    public void load() {
        storage.store(entry);

        KeyEntry loadedEntry = storage.load(alias);

        assertThat(loadedEntry, instanceOf(VirgilKeyEntry.class));
        assertEquals(entry.getName(), loadedEntry.getName());
        assertArrayEquals(entry.getValue(), loadedEntry.getValue());
        assertEquals(entry.getMetadata(), loadedEntry.getMetadata());
    }

    @Test(expected = KeyEntryNotFoundException.class)
    public void load_nullName() {
        storage.load(alias);
    }

    @Test(expected = KeyEntryNotFoundException.class)
    public void load_nonExisting() {
        storage.load(alias);
    }

    @Test
    public void delete() {
        storage.store(entry);
        storage.delete(alias);

        assertFalse(storage.exists(alias));
    }

    @Test(expected = KeyEntryNotFoundException.class)
    public void delete_nullName() {
        storage.delete(null);
    }

    @Test(expected = KeyEntryNotFoundException.class)
    public void delete_nonExisting() {
        storage.delete(alias);
    }

    @Test
    public void names_empty() {
        List<String> names = storage.names();
        assertNotNull(names);
        assertTrue(names.isEmpty());
    }

    @Test
    public void names() {
        storage.store(entry);
        List<String> names = storage.names();
        assertNotNull(names);
        assertEquals(1, names.size());
        assertEquals(entry.getName(), names.get(0));
    }

}
