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

package com.virgilsecurity.sdk.jsonWebToken;

import com.virgilsecurity.sdk.common.PropertyManager;
import com.virgilsecurity.sdk.crypto.Crypto;

public class JWTIntegrationTest extends PropertyManager {

    private Crypto crypto;

//    @Before
//    public void setUp() {
//        crypto = new VirgilCrypto();
//    }
//    @Test
//    public CardManager getCardManager(String getIdentity) throws CryptoException {
//        PrivateKey apiPrivateKey = crypto.importPrivateKey(ConvertionUtils.base64ToBytes(API_PRIVATE_KEY));
//
//        HashMap<String, String> data = new HashMap<>();
//        data.put("username", "my username");
//
//        AccessTokenBuilder tokenBuilder = new AccessTokenBuilder(ACCOUNT_ID,
//                                                                 APP_CARD_ID,
//                                                                 TimeSpan.fromTime(10, TimeUnit.MINUTES),
//                                                                 apiPrivateKey,
//                                                                 crypto);
//        String jwt = tokenBuilder.create(getIdentity, data);
//    }
}
