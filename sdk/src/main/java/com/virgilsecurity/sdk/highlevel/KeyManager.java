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
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

/**
 * The {@linkplain KeyManager} interface defines a list of methods to generate the {@link VirgilKey} and further them
 * storage in secure place.
 * 
 * @author Andrii Iakovenko
 *
 */
public interface KeyManager {

    /**
     * Generates a new {@link VirgilKey} with default parameters.
     * 
     * @return The generated key.
     */
    VirgilKey generate();

    /**
     * Loads the {@link VirgilKey} from current storage by specified key name.
     * 
     * @param keyName
     *            The name of the Key.
     * @return An instance of {@link VirgilKey} class.
     * @throws CryptoException 
     * @throws VirgilKeyIsNotFoundException
     *             If key not exists.
     */
    VirgilKey load(String keyName) throws VirgilKeyIsNotFoundException, CryptoException;

    /**
     * Loads the {@link VirgilKey} from current storage by specified key name.
     * 
     * @param keyName
     *            The name of the Key.
     * @param keyPassword
     *            The Key password.
     * @return An instance of {@link VirgilKey} class.
     * @throws VirgilKeyIsNotFoundException
     *             If key not exists.
     * @throws CryptoException 
     */
    VirgilKey load(String keyName, String keyPassword) throws VirgilKeyIsNotFoundException, CryptoException;

    /**
     * Removes the @ {@link VirgilKey} from the storage.
     * 
     * @param keyName
     *            The name of the Key.
     * @return This key manager.
     */
    KeyManager destroy(String keyName);

    /**
     * Imports the {@linkplain VirgilKey} from buffer.
     * 
     * @param keyBuffer
     *            The buffer with Key.
     * @return An instance of {@link VirgilKey} class.
     * @throws CryptoException 
     */
    VirgilKey importKey(VirgilBuffer keyBuffer) throws CryptoException;

    /**
     * Imports the {@linkplain VirgilKey} from buffer.
     * 
     * @param keyBuffer
     *            The buffer with Key.
     * @param keyPassword
     *            The Key password.
     * @return An instance of {@link VirgilKey} class.
     * @throws CryptoException 
     */
    VirgilKey importKey(VirgilBuffer keyBuffer, String keyPassword) throws CryptoException;

    /**
     * Imports the {@linkplain VirgilKey}.
     * 
     * @param privateKey
     *            The private key.
     * @return An instance of {@link VirgilKey} class.
     */
    VirgilKey importKey(PrivateKey privateKey);

}
