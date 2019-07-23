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

package com.virgilsecurity.sdk.androidutils.storage;

import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryAlreadyExistsException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.storage.KeyEntry;
import com.virgilsecurity.sdk.storage.KeyStorage;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.IOException;
import java.util.Set;
import java.util.UUID;

import static org.junit.Assert.*;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class StorageTest {

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    private KeyStorage storage;
    private KeyEntry entry;
    private File tmpDir;
    private String alias;

    @Before
    public void setUp() throws CryptoException {
        VirgilCrypto crypto = new VirgilCrypto();

        tmpDir = new File(InstrumentationRegistry.getContext().getFilesDir().getAbsolutePath()
                + File.separator + UUID.randomUUID().toString());
        storage = new AndroidKeyStorage(tmpDir.getAbsolutePath());

        VirgilKeyPair keyPair = crypto.generateKeyPair();

        alias = UUID.randomUUID().toString();

        entry = new AndroidKeyEntry();
        entry.setName(alias);
        entry.setValue(crypto.exportPrivateKey(keyPair.getPrivateKey()));
        entry.getMeta().put(UUID.randomUUID().toString(), UUID.randomUUID().toString());
    }

    @Test
    public void delete() {
        storage.store(entry);
        storage.delete(alias);

        assertFalse(storage.exists(alias));
    }

    @Test
    public void delete_nonExisting() {
        exceptionRule.expect(KeyEntryNotFoundException.class);
        storage.delete(alias);
    }

    @Test
    public void delete_nullName() {
        exceptionRule.expect(KeyEntryNotFoundException.class);
        storage.delete(null);
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
    public void exists_nullAlias() {
        assertFalse(storage.exists(null));
    }

    @Test
    public void exists_randomName() {
        assertFalse(storage.exists(UUID.randomUUID().toString()));
    }

    @Test
    public void load() {
        storage.store(entry);

        KeyEntry loadedEntry = storage.load(alias);

        assertTrue(loadedEntry instanceof AndroidKeyEntry);
        assertEquals(entry.getName(), loadedEntry.getName());
        assertArrayEquals(entry.getValue(), loadedEntry.getValue());
        assertEquals(entry.getMeta(), loadedEntry.getMeta());
    }

    @Test
    public void load_nonExisting() {
        exceptionRule.expect(KeyEntryNotFoundException.class);
        storage.load(alias);
    }

    @Test
    public void load_nullName() {
        exceptionRule.expect(KeyEntryNotFoundException.class);
        storage.load(alias);
    }

    @Test
    public void names() {
        storage.store(entry);
        Set<String> names = storage.names();
        assertNotNull(names);
        assertEquals(1, names.size());
        assertEquals(entry.getName(), names.iterator().next());
    }

    @Test
    public void names_empty() {
        Set<String> names = storage.names();
        assertNotNull(names);
        assertTrue(names.isEmpty());
    }

    @Test
    public void store() {
        storage.store(entry);

        assertTrue(storage.exists(alias));
    }

    @Test
    public void store_duplicated() {
        storage.store(entry);

        exceptionRule.expect(KeyEntryAlreadyExistsException.class);
        storage.store(entry);
    }
}
