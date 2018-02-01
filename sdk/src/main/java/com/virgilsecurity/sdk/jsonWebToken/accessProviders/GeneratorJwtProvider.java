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

package com.virgilsecurity.sdk.jsonWebToken.accessProviders;

import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jsonWebToken.JwtGenerator;
import com.virgilsecurity.sdk.jsonWebToken.TokenContext;
import com.virgilsecurity.sdk.utils.Validator;
import com.virgilsecurity.sdk.jsonWebToken.contract.AccessToken;
import com.virgilsecurity.sdk.jsonWebToken.contract.AccessTokenProvider;

import java.util.Map;

public class GeneratorJwtProvider implements AccessTokenProvider {

    private JwtGenerator jwtGenerator;
    private Map<String, String> additionalData;

    public GeneratorJwtProvider(JwtGenerator jwtGenerator) {
        Validator.checkIllegalAgrument(jwtGenerator, "GeneratorJwtProvider -> 'jwtGenerator' should not be null");

        this.jwtGenerator = jwtGenerator;
    }

    public GeneratorJwtProvider(JwtGenerator jwtGenerator, Map<String, String> additionalData) {
        Validator.checkIllegalAgrument(jwtGenerator, "GeneratorJwtProvider -> 'jwtGenerator' should not be null");
        Validator.checkIllegalAgrument(additionalData, "GeneratorJwtProvider -> 'additionalData' should not be null");

        this.jwtGenerator = jwtGenerator;
        this.additionalData = additionalData;
    }

    @Override public AccessToken getToken(TokenContext context) throws CryptoException {
        return jwtGenerator.generateToken(context.getIdentity(), additionalData);
    }

    public JwtGenerator getJwtGenerator() {
        return jwtGenerator;
    }

    public Map<String, String> getAdditionalData() {
        return additionalData;
    }
}
