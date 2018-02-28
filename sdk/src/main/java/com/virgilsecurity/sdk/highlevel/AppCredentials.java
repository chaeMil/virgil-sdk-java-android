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

import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

/**
 * Provides credentials for application authentication using AppID and AppKey retrieved from development deshboard.
 * 
 * @author Andrii Iakovenko
 *
 */
public class AppCredentials implements Credentials {

    /**
     * Application ID uniquely identifies your application in Virgil services, and it is also used to identify the
     * Virgil Card/Public key generated in a pair with application key.
     */
    private String appId;

    /**
     * Application key is representing a Private key that is used to perform creation and revocation of Virgil Cards
     * (Public key) in Virgil services. Also the application key can be used for cryptographic operations to take part
     * in application logic.
     */
    private VirgilBuffer appKey;

    /**
     * Application key password is used to protect the application key.
     */
    private String appKeyPassword;

    /* (non-Javadoc)
     * @see com.virgilsecurity.sdk.highlevel.Credentials#getAppKey(com.virgilsecurity.sdk.crypto.Crypto)
     */
    public PrivateKey getAppKey(Crypto crypto) throws CryptoException {
        PrivateKey key = crypto.importPrivateKey(this.appKey.getBytes(), this.appKeyPassword);
        return key;
    }

    /**
     * @return the appId
     */
    public String getAppId() {
        return appId;
    }

    /**
     * @param appId
     *            the appId to set
     */
    public void setAppId(String appId) {
        this.appId = appId;
    }

    /**
     * @return the appKey
     */
    public VirgilBuffer getAppKey() {
        return appKey;
    }

    /**
     * @param appKey
     *            the appKey to set
     */
    public void setAppKey(VirgilBuffer appKey) {
        this.appKey = appKey;
    }

    /**
     * @return the appKeyPassword
     */
    public String getAppKeyPassword() {
        return appKeyPassword;
    }

    /**
     * @param appKeyPassword
     *            the appKeyPassword to set
     */
    public void setAppKeyPassword(String appKeyPassword) {
        this.appKeyPassword = appKeyPassword;
    }

}