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
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.PrivateKeyExporter;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.utils.Tuple;

/**
 * Unit tests for {@code VirgilKeyStorage}
 *
 * @author Andrii Iakovenko
 * 
 * @see VirgilKeyStorage
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class PrivateKeyStorageTest {
    private VirgilCrypto crypto;
    private String keyName;
    private PrivateKey privateKey;

    @Mock
    private PrivateKeyExporter keyExporter;

    @Mock
    private KeyStorage keyStorage;
    private PrivateKeyStorage storage;

    @Before
    public void setUp() throws CryptoException {
        this.crypto = new VirgilCrypto();
        this.privateKey = this.crypto.generateKeys().getPrivateKey();
        this.keyName = UUID.randomUUID().toString();

        storage = new PrivateKeyStorage(keyExporter, keyStorage);

        // Configure mocks
        byte[] privateKeyData = ((VirgilPrivateKey) privateKey).getRawKey();
        when(this.keyExporter.exportPrivateKey(privateKey)).thenReturn(privateKeyData);
        when(this.keyExporter.importPrivateKey(privateKeyData))
                .thenReturn(this.crypto.importPrivateKey(privateKeyData));
    }

    @Test
    public void exists_nullAlias() {
        when(this.keyStorage.exists(null)).thenReturn(false);

        assertFalse(storage.exists(null));
    }

    @Test
    public void exists_randomName() {
        when(this.keyStorage.exists(Mockito.anyString())).thenReturn(false);

        assertFalse(storage.exists(UUID.randomUUID().toString()));
    }

    @Test
    public void exists() throws IOException, CryptoException {
        when(this.keyStorage.exists(this.keyName)).thenReturn(true);

        assertTrue(storage.exists(this.keyName));
    }

    @Test
    public void store() throws CryptoException {
        // when(this.keyStorage.exists(Mockito.anyString())).thenReturn(false);

        Map<String, String> meta = new HashMap<>();
        meta.put("key1", "value1");
        meta.put("key2", "value2");
        storage.store(this.privateKey, this.keyName, meta);

        verify(this.keyExporter, times(1)).exportPrivateKey(privateKey);

        ArgumentCaptor<KeyEntry> keyEntryCaptor = ArgumentCaptor.forClass(KeyEntry.class);
        verify(this.keyStorage, times(1)).store(keyEntryCaptor.capture());

        KeyEntry keyEntry = keyEntryCaptor.getValue();
        assertNotNull(keyEntry);
        assertEquals(this.keyName, keyEntry.getName());
        assertArrayEquals(((VirgilPrivateKey) this.privateKey).getRawKey(), keyEntry.getValue());
        assertNotNull(keyEntry.getMeta());
        assertEquals(meta, keyEntry.getMeta());
    }

    @Test
    public void store_noMeta() throws CryptoException {
        // when(this.keyStorage.exists(Mockito.anyString())).thenReturn(false);
        storage.store(this.privateKey, this.keyName, Collections.EMPTY_MAP);

        verify(this.keyExporter, times(1)).exportPrivateKey(privateKey);

        ArgumentCaptor<KeyEntry> keyEntryCaptor = ArgumentCaptor.forClass(KeyEntry.class);
        verify(this.keyStorage, times(1)).store(keyEntryCaptor.capture());

        KeyEntry keyEntry = keyEntryCaptor.getValue();
        assertNotNull(keyEntry);
        assertEquals(this.keyName, keyEntry.getName());
        assertArrayEquals(((VirgilPrivateKey) this.privateKey).getRawKey(), keyEntry.getValue());
        assertNotNull(keyEntry.getMeta());
        assertTrue(keyEntry.getMeta().isEmpty());
    }

    @Test
    public void load() throws CryptoException {
        Map<String, String> meta = new HashMap<>();
        meta.put("key1", "value1");
        meta.put("key2", "value2");
        KeyEntry entry = new JsonKeyEntry(this.keyName, this.keyExporter.exportPrivateKey(this.privateKey));
        entry.setMeta(meta);
        when(this.keyStorage.load(this.keyName)).thenReturn(entry);

        Tuple<PrivateKey, Map<String, String>> keyData = storage.load(this.keyName);
        assertNotNull(keyData);

        PrivateKey key = keyData.getLeft();
        assertNotNull(key);
        assertThat(key, instanceOf(VirgilPrivateKey.class));
        assertEquals(this.privateKey, key);

        assertEquals(meta, keyData.getRight());
    }

    @Test
    public void load_noMeta() throws CryptoException {
        KeyEntry entry = new JsonKeyEntry(this.keyName, this.keyExporter.exportPrivateKey(this.privateKey));
        when(this.keyStorage.load(this.keyName)).thenReturn(entry);

        Tuple<PrivateKey, Map<String, String>> keyData = storage.load(this.keyName);
        assertNotNull(keyData);

        PrivateKey key = keyData.getLeft();
        assertNotNull(key);
        assertThat(key, instanceOf(VirgilPrivateKey.class));
        assertEquals(this.privateKey, key);

        assertTrue(keyData.getRight().isEmpty());
    }

    @Test(expected = KeyEntryNotFoundException.class)
    public void load_nullName() throws CryptoException {
        when(this.keyStorage.load(null)).thenThrow(KeyEntryNotFoundException.class);
        storage.load(null);
    }

    @Test(expected = KeyEntryNotFoundException.class)
    public void load_nonExisting() throws CryptoException {
        when(this.keyStorage.load(this.keyName)).thenThrow(KeyEntryNotFoundException.class);
        storage.load(this.keyName);
    }

    @Test
    public void delete() {
        storage.delete(this.keyName);

        ArgumentCaptor<String> keyNameCaptor = ArgumentCaptor.forClass(String.class);
        verify(this.keyStorage, times(1)).delete(keyNameCaptor.capture());

        assertEquals(this.keyName, keyNameCaptor.getValue());
    }

    @Test(expected = KeyEntryNotFoundException.class)
    public void delete_nullName() {
        doThrow(KeyEntryNotFoundException.class).when(this.keyStorage).delete(null);

        storage.delete(null);
    }

    @Test(expected = KeyEntryNotFoundException.class)
    public void delete_nonExisting() {
        doThrow(KeyEntryNotFoundException.class).when(this.keyStorage).delete(this.keyName);

        storage.delete(this.keyName);
    }

    @Test
    public void names_empty() {
        when(this.keyStorage.names()).thenReturn(Collections.EMPTY_LIST);

        List<String> names = storage.names();
        assertNotNull(names);
        assertTrue(names.isEmpty());
    }

    @Test
    public void names() {
        when(this.keyStorage.names()).thenReturn(Arrays.asList("key1"));

        List<String> names = storage.names();
        assertNotNull(names);
        assertEquals(1, names.size());
        assertEquals("key1", names.get(0));
    }

}
