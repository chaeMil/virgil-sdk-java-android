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

import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.exception.NullArgumentException;

/**
 * The {@link VirgilCardCrypto} class provides a cryptographic operations in applications, such as hashing, signature
 * generation and verification, and encryption and decryption.
 *
 * @see CardCrypto
 * @see PrivateKey
 * @see PublicKey
 * @see VirgilCrypto
 */
public class VirgilCardCrypto implements CardCrypto {

    private VirgilCrypto virgilCrypto;

    /**
     * Instantiates a new Virgil card crypto.
     */
    public VirgilCardCrypto() {
        this.virgilCrypto = new VirgilCrypto();
    }

    /**
     * Example of usage:
     * 
     * <pre>
     * {
     *     &#64;code
     *     VirgilCardCrypto crypto = new VirgilCardCrypto();
     * }
     * </pre>
     */
    @Override
    public byte[] exportPublicKey(PublicKey publicKey) throws CryptoException {
        if (publicKey == null) {
            throw new NullArgumentException("publicKey");
        }
        if (!(publicKey instanceof VirgilPublicKey))
            throw new CryptoException("VirgilCrypto -> 'publicKey' should be of 'VirgilPublicKey' type");

        return virgilCrypto.exportPublicKey((VirgilPublicKey) publicKey);
    }

    @Override
    public byte[] generateSHA512(byte[] data) throws CryptoException {
        return virgilCrypto.generateHash(data, HashAlgorithm.SHA512);
    }

    /**
     * Example of usage:
     * 
     * <pre>
     * {
     *     &#64;code
     *     VirgilCardCrypto crypto = new VirgilCardCrypto();
     * }
     * </pre>
     */
    @Override
    public byte[] generateSignature(byte[] data, PrivateKey privateKey) throws CryptoException {
        if (privateKey == null) {
            throw new NullArgumentException("privateKey");
        }
        if (!(privateKey instanceof VirgilPrivateKey)) {
            throw new CryptoException("VirgilCrypto -> 'privateKey' should be of 'VirgilPrivateKey' type");
        }

        return virgilCrypto.generateSignature(data, (VirgilPrivateKey) privateKey);
    }

    /**
     * Gets virgil crypto.
     *
     * @return the virgil crypto
     */
    public VirgilCrypto getVirgilCrypto() {
        return virgilCrypto;
    }

    /**
     * Example of usage:
     * 
     * <pre>
     * {
     *     &#64;code
     *     VirgilCardCrypto crypto = new VirgilCardCrypto();
     * }
     * </pre>
     * <p>
     * How to get exportedPublicKey see the {@link #exportPublicKey(PublicKey)}
     */
    @Override
    public PublicKey importPublicKey(byte[] data) throws CryptoException {
        return virgilCrypto.importPublicKey(data);
    }

    /**
     * Example of usage:
     * 
     * <pre>
     * {
     *     &#64;code
     *     VirgilCardCrypto crypto = new VirgilCardCrypto();
     * }
     * </pre>
     * <p>
     * How to get signature see the {@link #generateSignature(byte[], PrivateKey)} How to get exportedPublicKey see the
     * {@link #exportPublicKey(PublicKey)}
     */
    @Override
    public boolean verifySignature(byte[] signature, byte[] data, PublicKey publicKey) throws CryptoException {
        if (publicKey == null) {
            throw new NullArgumentException("publicKey");
        }
        if (!(publicKey instanceof VirgilPublicKey)) {
            throw new CryptoException("VirgilCrypto -> 'publicKey' should be of 'VirgilPublicKey' type");
        }

        return virgilCrypto.verifySignature(signature, data, (VirgilPublicKey) publicKey);
    }
}
