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

/**
 * The {@link VirgilPrivateKeyExporter} represents and object that implements {@link PrivateKeyExporter} and provides a
 * list of methods that lets user to export and import private key.
 */
public class VirgilPrivateKeyExporter implements PrivateKeyExporter {

    private VirgilCrypto virgilCrypto;
    private String password;

    /**
     * Create new instance of {@link VirgilPrivateKeyExporter} using {@link VirgilCrypto} with default {@link KeysType}
     * - {@code FAST_EC_ED25519}.
     */
    public VirgilPrivateKeyExporter() {
        virgilCrypto = new VirgilCrypto(KeysType.FAST_EC_ED25519);
    }

    /**
     * Create new instance of {@link VirgilPrivateKeyExporter} using {@link VirgilCrypto} with default {@link KeysType}
     * - {@code FAST_EC_ED25519} and specified {@code password}.
     *
     * @param password
     *            The password for private key.
     */
    public VirgilPrivateKeyExporter(String password) {
        this.password = password;

        virgilCrypto = new VirgilCrypto(KeysType.FAST_EC_ED25519);
    }

    /**
     * Create new instance of {@link VirgilPrivateKeyExporter}.
     *
     * @param virgilCrypto
     *            The {@link VirgilCrypto}.
     */
    public VirgilPrivateKeyExporter(VirgilCrypto virgilCrypto) {
        if (virgilCrypto == null)
            throw new IllegalArgumentException("VirgilPrivateKeyExporter -> 'virgilCrypto' should not be null");

        this.virgilCrypto = virgilCrypto;
    }

    /**
     * Create new instance of {@link VirgilPrivateKeyExporter} with specified {@code password}.
     *
     * @param password
     *            The password for private key.
     */
    public VirgilPrivateKeyExporter(VirgilCrypto virgilCrypto, String password) {
        if (virgilCrypto == null)
            throw new IllegalArgumentException("VirgilPrivateKeyExporter -> 'virgilCrypto' should not be null");

        this.virgilCrypto = virgilCrypto;
        this.password = password;
    }

    /**
     * Exports the {@code privateKey} into material representation. If {@link VirgilCrypto} was instantiated with
     * {@code password} then it will be used to export private key.
     *
     * @param privateKey
     *            The private key.
     * @return Private key in material representation of {@code byte[]}.
     * @throws CryptoException
     *             if problems occurred while exporting key.
     */
    public byte[] exportPrivateKey(PrivateKey privateKey) throws CryptoException {
        if (!(privateKey instanceof VirgilPrivateKey))
            throw new CryptoException("VirgilAccessTokenSigner -> 'privateKey' should be of 'VirgilPrivateKey' type");

        return virgilCrypto.exportPrivateKey((VirgilPrivateKey) privateKey, password);
    }

    /**
     * Imports the private key from its material representation. If {@link VirgilCrypto} was instantiated with
     * {@code password} then it will be used to import private key.
     *
     * @param data
     *            The private key material representation bytes.
     * @return The instance of {@link PrivateKey} imported.
     * @throws CryptoException
     *             if problems occurred while importing key.
     */
    public PrivateKey importPrivateKey(byte[] data) throws CryptoException {
        return virgilCrypto.importPrivateKey(data, password);
    }
}
