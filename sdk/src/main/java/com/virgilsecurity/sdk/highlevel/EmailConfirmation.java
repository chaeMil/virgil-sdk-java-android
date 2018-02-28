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

import com.virgilsecurity.sdk.client.VirgilClient;
import com.virgilsecurity.sdk.client.model.dto.Token;

/**
 * @author Andrii Iakovenko
 *
 */
public class EmailConfirmation extends IdentityConfirmation {

    private String confirmationCode;

    /**
     * Create new instance of {@link EmailConfirmation}.
     * 
     * @param confirmationCode The confirmation code from email.
     */
    public EmailConfirmation(String confirmationCode) {
        super();
        this.confirmationCode = confirmationCode;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.highlevel.IdentityConfirmation#confirmAndGrabValidationToken(com.virgilsecurity.sdk.
     * highlevel.IdentityVerificationAttempt, com.virgilsecurity.sdk.client.VirgilClient)
     */
    @Override
    String confirmAndGrabValidationToken(IdentityVerificationAttempt attempt, VirgilClient client) {
        Token token = new Token(attempt.getTimeToLive(), attempt.getCountToLive());
        String confirmatonToken = client.confirmIdentity(attempt.getActionId(), this.confirmationCode, token);

        return confirmatonToken;
    }

}
