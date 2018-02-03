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
package com.virgilsecurity.sdk.crypto;

import java.io.Serializable;
import java.util.Arrays;

/**
 * A private key.
 *
 * @see VirgilCrypto
 * @see VirgilPublicKey
 */
public class VirgilPrivateKey implements PrivateKey, Serializable {

    private static final long serialVersionUID = 3949844179494530851L;

    /**
     * The Private key identifier
     */
    private byte[] identifier;

    /**
     * The Private key rawKey
     */
    private byte[] rawKey;

    /**
     * Create a new instance of {@code VirgilPrivateKey}
     */
    public VirgilPrivateKey() {
    }

    /**
     * Create a new instance of {@code VirgilPrivateKey}
     *
     * @param identifier
     *            the key identifier.
     * @param rawKey
     *            the key rawKey.
     */
    public VirgilPrivateKey(byte[] identifier, byte[] rawKey) {
        this.identifier = identifier;
        this.rawKey = rawKey;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        VirgilPrivateKey other = (VirgilPrivateKey) obj;
        if (!Arrays.equals(identifier, other.identifier))
            return false;
        if (!Arrays.equals(rawKey, other.rawKey))
            return false;
        return true;
    }


    /**
     * Get identifier byte [ ].
     *
     * @return the byte [ ]
     */
    public byte[] getIdentifier() {
        return identifier;
    }


    /**
     * Get raw key byte [ ].
     *
     * @return the byte [ ]
     */
    public byte[] getRawKey() {
        return rawKey;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(identifier);
        result = prime * result + Arrays.hashCode(rawKey);
        return result;
    }


    /**
     * Sets identifier.
     *
     * @param identifier the identifier
     */
    public void setIdentifier(byte[] identifier) {
        this.identifier = identifier;
    }

    /**
     * Sets raw key.
     *
     * @param rawKey the rawKey to set
     */
    public void setRawKey(byte[] rawKey) {
        this.rawKey = rawKey;
    }

}
