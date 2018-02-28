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

import com.virgilsecurity.sdk.client.VirgilAuthClient;
import com.virgilsecurity.sdk.exception.NullArgumentException;

/**
 * The @ {@link VirgilApi} class is a high-level API that provides easy access to Virgil Security services and allows to
 * perform cryptographic operations by using two domain entities {@link VirgilKey} and {@link VirgilCard}. Where the
 * {@link VirgilKey} is an entity that represents a user's Private key, and the {@link VirgilCard} is the entity that
 * represents user's identity and a Public key.
 * 
 * @author Andrii Iakovenko
 *
 */
public class VirgilApiImpl implements VirgilApi {

    private VirgilApiContext context;

    private KeyManager keyManager;
    private CardManager cardManager;
    private VirgilAuthClient authClient;

    /**
     * Create new instance of {@link VirgilApiImpl}.
     */
    public VirgilApiImpl() {
        this.context = new VirgilApiContext();
        init();
    }

    /**
     * Create new instance of {@link VirgilApiImpl}.
     * 
     * @param accessToken
     *            The access token.
     */
    public VirgilApiImpl(String accessToken) {
        this.context = new VirgilApiContext(accessToken);
        init();
    }

    /**
     * Create new instance of {@link VirgilApiImpl}.
     * 
     * @param context
     *            The configuration.
     */
    public VirgilApiImpl(VirgilApiContext context) {
        if (context == null) {
            throw new NullArgumentException("context");
        }
        this.context = context;
        init();
    }

    private void init() {
        this.keyManager = new VirgilKeyManager(this.context);
        this.cardManager = new VirgilCardManager(this.context);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.highlevel.VirgilApi#getKeys()
     */
    @Override
    public KeyManager getKeys() {
        return keyManager;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.highlevel.VirgilApi#getCards()
     */
    @Override
    public CardManager getCards() {
        return cardManager;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.highlevel.VirgilApi#getAuth()
     */
    @Override
    public VirgilAuthClient getAuth() {
        if (this.authClient == null) {
            authClient = new VirgilAuthClient(context.getClientContext());
        }
        return this.authClient;
    }

}
