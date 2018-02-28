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
 * A public key.
 * 
 * @see VirgilCrypto
 * @see PublicKey
 * 
 * @author Andrii Iakovenko
 */
public class VirgilPublicKey implements PublicKey, Serializable {

    private static final long serialVersionUID = 1806825984983845090L;

    /** The Public key identifier */
    private byte[] id;

    /** The Public key value */
    private byte[] value;

    /**
     * Create a new instance of {@code VirgilPublicKey}
     *
     */
    VirgilPublicKey() {
    }

    /**
     * Create a new instance of {@code VirgilPublicKey}
     *
     * @param id
     * @param value
     */
    VirgilPublicKey(byte[] id, byte[] value) {
        this.id = id;
        this.value = value;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.PublicKey#getId()
     */
    public byte[] getId() {
        return id;
    }

    /**
     * Set the Public key hash.
     * 
     * @param id
     *            the Id to set
     */
    public void setId(byte[] id) {
        this.id = id;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.PublicKey#getValue()
     */
    public byte[] getValue() {
        return value;
    }

    /**
     * Set the Public key value.
     * 
     * @param value
     *            the value to set
     */
    public void setValue(byte[] value) {
        this.value = value;
    }

}
