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

/**
 * The key pair.
 */
public class KeyPairVirgiled {

    private VirgilPublicKey publicKey;

    private VirgilPrivateKey privateKey;

    /**
     * Create a new instance of {@code KeyPairVirgiled}
     *
     */
    public KeyPairVirgiled() {
    }

    /**
     * Create a new instance of {@code KeyPair}
     *
     * @param publicKey
     *            the Virgil public key.
     * @param privateKey
     *            the Virgil private key.
     */
    public KeyPairVirgiled(VirgilPublicKey publicKey, VirgilPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    /**
     * @return the Virgil publicKey
     */
    public VirgilPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * @param publicKey
     *            the Virgil public key to set
     */
    public void setPublicKey(VirgilPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * @return the Virgil privateKey
     */
    public VirgilPrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * @param privateKey
     *            the Virgil privateKey to set
     */
    public void setPrivateKey(VirgilPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

}
