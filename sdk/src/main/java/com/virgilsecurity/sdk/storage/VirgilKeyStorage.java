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
package com.virgilsecurity.sdk.storage;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.nio.file.InvalidPathException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryAlreadyExistsException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyStorageException;

/**
 * Virgil implementation of a storage facility for cryptographic keys.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilKeyStorage implements KeyStorage {

    private String keysPath;

    /**
     * Create a new instance of {@code VirgilKeyStorage}
     *
     */
    public VirgilKeyStorage() {
        StringBuilder path = new StringBuilder(System.getProperty("user.home"));
        path.append(File.separator).append("VirgilSecurity");
        path.append(File.separator).append("Keys");

        this.keysPath = path.toString();
    }

    /**
     * Create a new instance of {@code VirgilKeyStorage}
     *
     * @param keysPath
     *            The path to key storage folder.
     */
    public VirgilKeyStorage(String keysPath) {
        this.keysPath = keysPath;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.KeyStore#store(com.virgilsecurity.sdk. crypto.KeyEntry)
     */
    @Override
    public void store(KeyEntry keyEntry) {
        File dir = new File(keysPath);

        if (dir.exists()) {
            if (!dir.isDirectory()) {
                throw new InvalidPathException(keysPath, "Is not a directory");
            }
        } else {
            dir.mkdirs();
        }

        String name = keyEntry.getName();
        if (exists(name)) {
            throw new KeyEntryAlreadyExistsException();
        }

        String json = getGson().toJson(keyEntry);
        File file = new File(dir, name.toLowerCase());
        try (FileOutputStream os = new FileOutputStream(file)) {
            os.write(json.getBytes(Charset.forName("UTF-8")));
        } catch (Exception e) {
            throw new KeyStorageException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.KeyStore#load(java.lang.String)
     */
    @Override
    public KeyEntry load(String keyName) {
        if (!exists(keyName)) {
            throw new KeyEntryNotFoundException();
        }

        File file = new File(keysPath, keyName.toLowerCase());
        try (FileInputStream is = new FileInputStream(file)) {
            ByteArrayOutputStream os = new ByteArrayOutputStream();

            byte[] buffer = new byte[4096];
            int n = 0;
            while (-1 != (n = is.read(buffer))) {
                os.write(buffer, 0, n);
            }

            byte[] bytes = os.toByteArray();

            VirgilKeyEntry entry = getGson().fromJson(new String(bytes, Charset.forName("UTF-8")),
                    VirgilKeyEntry.class);
            entry.setName(keyName);

            return entry;
        } catch (Exception e) {
            throw new KeyStorageException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.KeyStore#exists(java.lang.String)
     */
    @Override
    public boolean exists(String keyName) {
        if (keyName == null) {
            return false;
        }
        File file = new File(keysPath, keyName.toLowerCase());
        return file.exists();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.KeyStore#delete(java.lang.String)
     */
    @Override
    public void delete(String keyName) {
        if (!exists(keyName)) {
            throw new KeyEntryNotFoundException();
        }

        File file = new File(keysPath, keyName.toLowerCase());
        file.delete();
    }

    private Gson getGson() {
        GsonBuilder builder = new GsonBuilder();
        Gson gson = builder.create();

        return gson;
    }

}
