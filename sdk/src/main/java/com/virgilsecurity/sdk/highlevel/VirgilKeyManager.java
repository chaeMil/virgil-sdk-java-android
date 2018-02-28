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

import com.virgilsecurity.sdk.client.exceptions.VirgilKeyIsNotFoundException;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.storage.KeyEntry;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilKeyManager implements KeyManager {

    private VirgilApiContext context;

    /**
     * Create new instance of {@link VirgilKeyManager}.
     * 
     * @param context
     *            The context.
     */
    public VirgilKeyManager(VirgilApiContext context) {
        this.context = context;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.highlevel.KeyManager#generate()
     */
    @Override
    public VirgilKey generate() {
        KeyPair keyPair = this.context.getCrypto().generateKeys();
        return new VirgilKey(this.context, keyPair.getPrivateKey());
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.highlevel.KeyManager#load(java.lang.String)
     */
    @Override
    public VirgilKey load(String keyName) throws VirgilKeyIsNotFoundException, CryptoException {
        return load(keyName, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.highlevel.KeyManager#load(java.lang.String, java.lang.String)
     */
    @Override
    public VirgilKey load(String keyName, String keyPassword) throws VirgilKeyIsNotFoundException, CryptoException {
        KeyEntry keyEntry = this.context.getKeyStorage().load(keyName);
        PrivateKey privateKey = this.context.getCrypto().importPrivateKey(keyEntry.getValue(), keyPassword);
        VirgilKey virgilKey = new VirgilKey(this.context, privateKey);
        return virgilKey;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.highlevel.KeyManager#destroy(java.lang.String)
     */
    @Override
    public KeyManager destroy(String keyName) {
        this.context.getKeyStorage().delete(keyName);

        return this;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.highlevel.KeyManager#importKey(com.virgilsecurity.sdk.highlevel.VirgilBuffer)
     */
    @Override
    public VirgilKey importKey(VirgilBuffer keyBuffer) throws CryptoException {
        return importKey(keyBuffer, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.highlevel.KeyManager#importKey(com.virgilsecurity.sdk.highlevel.VirgilBuffer,
     * java.lang.String)
     */
    @Override
    public VirgilKey importKey(VirgilBuffer keyBuffer, String keyPassword) throws CryptoException {
        PrivateKey privateKey = this.context.getCrypto().importPrivateKey(keyBuffer.getBytes(), keyPassword);
        VirgilKey virgilKey = new VirgilKey(this.context, privateKey);

        return virgilKey;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.highlevel.KeyManager#importKey(com.virgilsecurity.sdk.crypto.PrivateKey)
     */
    @Override
    public VirgilKey importKey(PrivateKey privateKey) {
        VirgilKey virgilKey = new VirgilKey(this.context, privateKey);
        return virgilKey;
    }

}
