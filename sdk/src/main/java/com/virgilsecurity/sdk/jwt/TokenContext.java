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

package com.virgilsecurity.sdk.jwt;

/**
 * The {@link TokenContext} class represents set of data
 * that helps to get token.
 */
public class TokenContext {

    private String identity;
    private String operation;
    private boolean forceReload;

    /**
     * Instantiates a new Token context.
     *
     * @param operation   the operation that is token used for
     * @param forceReload {@code true} if token should be reloaded every time
     * {@link com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider#getToken(TokenContext)}
     *                                method is called, otherwise {@code false}
     */
    public TokenContext(String operation, boolean forceReload) {
        this.operation = operation;
        this.forceReload = forceReload;
    }

    /**
     * Instantiates a new Token context.
     *
     * @param identity    the identity
     * @param operation   the operation that is token used for
     * @param forceReload {@code true} if token should be reloaded every time
     * {@link com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider#getToken(TokenContext)}
     *                                method is called, otherwise {@code false}
     */
    public TokenContext(String identity, String operation, boolean forceReload) {
        this.identity = identity;
        this.operation = operation;
        this.forceReload = forceReload;
    }

    /**
     * Gets identity.
     *
     * @return the identity
     */
    public String getIdentity() {
        return identity;
    }

    /**
     * Sets identity.
     *
     * @param identity the identity
     */
    public void setIdentity(String identity) {
        this.identity = identity;
    }

    /**
     * Gets operation that is token used for.
     *
     * @return the operation that is token used for
     */
    public String getOperation() {
        return operation;
    }

    /**
     * Sets operation that is token used for.
     *
     * @param operation the operation that is token used for
     */
    public void setOperation(String operation) {
        this.operation = operation;
    }

    /**
     * Whether token should be reloaded every time
     * {@link com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider#getToken(TokenContext)}
     *                                method is called.
     *
     * @return {@code true} if token should be reloaded every time
     * {@link com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider#getToken(TokenContext)}
     *                                method is called, otherwise {@code false}
     */
    public boolean isForceReload() {
        return forceReload;
    }
}
