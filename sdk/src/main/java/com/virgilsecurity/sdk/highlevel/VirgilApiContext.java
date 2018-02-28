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

import java.util.Collection;

import com.virgilsecurity.sdk.client.VirgilClient;
import com.virgilsecurity.sdk.client.VirgilClientContext;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.device.DeviceManager;
import com.virgilsecurity.sdk.device.DefaultDeviceManager;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.storage.KeyStorage;
import com.virgilsecurity.sdk.storage.VirgilKeyStorage;
import com.virgilsecurity.sdk.utils.VirgilCardValidator;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilApiContext {

    private Crypto crypto;
    private KeyStorage keyStorage;
    private DeviceManager deviceManager;
    private VirgilClient virgilClient;

    private String accessToken;
    private Credentials credentials;
    private Collection<CardVerifierInfo> cardVerifiers;
    private VirgilClientContext clientContext;

    /**
     * Create new instance of {@link VirgilApiContext}.
     */
    public VirgilApiContext() {
    }

    /**
     * Create new instance of {@link VirgilApiContext}.
     * 
     * @param accessToken
     *            The access token.
     */
    public VirgilApiContext(String accessToken) {
        this.accessToken = accessToken;
    }

    /**
     * Gets a crypto API that represents a set of methods for dealing with low-level cryptographic primitives and
     * algorithms.
     * 
     * @return the crypto API.
     */
    public Crypto getCrypto() {
        if (crypto == null) {
            crypto = new VirgilCrypto();
        }
        return crypto;
    }

    /**
     * Sets a crypto API that represents a set of methods for dealing with low-level cryptographic primitives and
     * algorithms.
     * 
     * @param crypto
     *            the crypto to set.
     */
    public void setCrypto(Crypto crypto) {
        if (crypto == null) {
            throw new NullArgumentException("crypto");
        }
        if (this.crypto != null) {
            throw new IllegalArgumentException("Crypto is already set");
        }
        this.crypto = crypto;
        this.crypto = crypto;
    }

    /**
     * Gets a cryptographic keys storage.
     * 
     * @return the keyStorage
     */
    public KeyStorage getKeyStorage() {
        if (this.keyStorage == null) {
            this.keyStorage = new VirgilKeyStorage();
        }
        return keyStorage;
    }

    /**
     * Sets a cryptographic keys storage.
     * 
     * @param keyStorage
     *            the key storage to set
     */
    public void setKeyStorage(KeyStorage keyStorage) {
        if (keyStorage == null) {
            throw new NullArgumentException("keyStorage");
        }
        if (this.keyStorage != null) {
            throw new IllegalArgumentException("Keys storage is already set");
        }
        this.keyStorage = keyStorage;
    }

    /**
     * Gets the instance that represents an information about current device.
     * 
     * @return the deviceManager
     */
    public DeviceManager getDeviceManager() {
        if (deviceManager == null) {
            deviceManager = new DefaultDeviceManager();
        }
        return deviceManager;
    }

    /**
     * Sets the instance that represents an information about current device.
     * 
     * @param deviceManager
     *            the deviceManager to set
     */
    public void setDeviceManager(DeviceManager deviceManager) {
        if (deviceManager == null) {
            throw new NullArgumentException("deviceManager");
        }
        this.deviceManager = deviceManager;
    }

    /**
     * Gets a Virgil Security services client.
     * 
     * @return the client
     */
    public VirgilClient getClient() {
        if (this.virgilClient == null) {
            if (this.clientContext == null) {
                this.virgilClient = new VirgilClient(this.accessToken);
            } else {
                this.virgilClient = new VirgilClient(this.clientContext);
            }
            initClient();
        }
        return virgilClient;
    }

    private void initClient() {
        VirgilCardValidator validator = new VirgilCardValidator(getCrypto());
        if (this.cardVerifiers != null) {
            for (CardVerifierInfo verifierInfo : this.cardVerifiers) {
                validator.addVerifier(verifierInfo.getCardId(), verifierInfo.getPublicKeyData().getBytes());
            }
        }

        this.virgilClient.setCardValidator(validator);
    }

    /**
     * Gets the access token provides an authenticated secure access to the Virgil Security services. The access token
     * also allows the API to associate your app requests with your Virgil Security developer's account.
     * 
     * @return the accessToken
     */
    public String getAccessToken() {
        return accessToken;
    }

    /**
     * Sets the access token provides an authenticated secure access to the Virgil Security services. The access token
     * also allows the API to associate your app requests with your Virgil Security developer's account. It's not
     * required if client context has been set.
     * 
     * @param accessToken
     *            the accessToken to set
     */
    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    /**
     * Gets the application authentication credentials.
     * 
     * @return the credentials
     */
    public Credentials getCredentials() {
        return credentials;
    }

    /**
     * Sets the application authentication credentials.
     * 
     * @param credentials
     *            the credentials to set
     */
    public void setCredentials(Credentials credentials) {
        this.credentials = credentials;
    }

    /**
     * Gets a list of Virgil Card verifiers.
     * 
     * @return the cardVerifiers
     */
    public Collection<CardVerifierInfo> getCardVerifiers() {
        return cardVerifiers;
    }

    /**
     * Sets a list of Virgil Card verifiers.
     * 
     * @param cardVerifiers
     *            the cardVerifiers to set
     */
    public void setCardVerifiers(Collection<CardVerifierInfo> cardVerifiers) {
        if (cardVerifiers == null) {
            throw new NullArgumentException("cardVerifiers");
        }
        this.cardVerifiers = cardVerifiers;
    }

    /**
     * Gets the client context.
     * 
     * @return the clientContext
     */
    public VirgilClientContext getClientContext() {
        return clientContext;
    }

    /**
     * Sets the client parameters.
     * 
     * @param clientContext
     *            the clientContext to set
     */
    public void setClientContext(VirgilClientContext clientContext) {
        this.clientContext = clientContext;
    }

}
