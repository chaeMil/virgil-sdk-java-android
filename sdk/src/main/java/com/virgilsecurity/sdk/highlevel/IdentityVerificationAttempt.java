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

import com.virgilsecurity.sdk.client.exceptions.VirgilClientException;

/**
 * 
 * The {@linkplain IdentityVerificationAttempt} class provides information about identity verification process.
 * 
 * @author Andrii Iakovenko
 *
 */
public class IdentityVerificationAttempt {

    private VirgilApiContext context;

    private String actionId;

    private String identity;

    private String identityType;

    private long timeToLive;

    private long countToLive;

    /**
     * Create new instance of {@link IdentityVerificationAttempt}.
     * 
     * @param context The context.
     */
    public IdentityVerificationAttempt(VirgilApiContext context) {
        this.context = context;
        
        this.timeToLive = 3600;
        this.countToLive = 1;
    }

    /**
     * Gets the operation action ID.
     * 
     * @return the actionId The action identifier.
     */
    public String getActionId() {
        return actionId;
    }

    /**
     * Sets the operation action ID.
     * 
     * @param actionId
     *            the action identifier to set.
     */
    void setActionId(String actionId) {
        this.actionId = actionId;
    }

    /**
     * Gets the identity value.
     * 
     * @return the identity.
     */
    public String getIdentity() {
        return identity;
    }

    /**
     * Sets the identity value.
     * 
     * @param identity
     *            the identity to set.
     */
    void setIdentity(String identity) {
        this.identity = identity;
    }

    /**
     * Gets the type of the identity.
     * 
     * @return the identity type.
     */
    public String getIdentityType() {
        return identityType;
    }

    /**
     * Sets the type of the identity.
     * 
     * @param identityType
     *            the identity type to set.
     */
    void setIdentityType(String identityType) {
        this.identityType = identityType;
    }

    /**
     * Gets the time to live.
     * 
     * @return the timeToLive.
     */
    public long getTimeToLive() {
        return timeToLive;
    }

    /**
     * Sets the time to live.
     * 
     * @param timeToLive
     *            the timeToLive to set.
     */
    void setTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
    }

    /**
     * Gets the count to live.
     * 
     * @return the countToLive.
     */
    public long getCountToLive() {
        return countToLive;
    }

    /**
     * Sets the count to live.
     * 
     * @param countToLive
     *            the countToLive to set.
     */
    void setCountToLive(long countToLive) {
        this.countToLive = countToLive;
    }

    /**
     * Confirms an identity and generates a validation token that can be used to perform operations like Publish and
     * Revoke global Cards.
     * 
     * @param confirmation
     *            The confirmation.
     * @return A new instance of {@link IdentityValidationToken} class.
     * @throws VirgilClientException 
     */
    public IdentityValidationToken confirm(IdentityConfirmation confirmation) throws VirgilClientException {
        if (confirmation == null) {
            throw new VirgilClientException("Not supported");
        }

        String validationToken = confirmation.confirmAndGrabValidationToken(this, this.context.getClient());
        return new IdentityValidationToken(validationToken);
    }

}
