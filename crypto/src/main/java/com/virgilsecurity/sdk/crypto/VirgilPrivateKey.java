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
package com.virgilsecurity.sdk.crypto;

import java.io.Serializable;

/**
 * A private key.
 * 
 * @see VirgilCrypto
 * @see VirgilPublicKey
 * 
 * @author Andrii Iakovenko
 */
public class VirgilPrivateKey implements PrivateKey, Serializable {

    private static final long serialVersionUID = -3437950195416086773L;

    private byte[] id;

    /** The Private key value */
    private byte[] value;

    /**
     * Create a new instance of {@code VirgilPrivateKey}
     *
     */
    public VirgilPrivateKey() {
    }

    /**
     * Create a new instance of {@code VirgilPrivateKey}
     *
     * @param id
     *            the key identifier.
     * @param value
     *            the key value.
     */
    public VirgilPrivateKey(byte[] id, byte[] value) {
        this.id = id;
        this.value = value;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.PrivateKey#getId()
     */
    public byte[] getId() {
        return id;
    }

    /**
     * @param id
     *            the id to set.
     */
    public void setId(byte[] id) {
        this.id = id;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.PrivateKey#getValue()
     */
    public byte[] getValue() {
        return value;
    }

    /**
     * @param value
     *            the value to set
     */
    public void setValue(byte[] value) {
        this.value = value;
    }

}
