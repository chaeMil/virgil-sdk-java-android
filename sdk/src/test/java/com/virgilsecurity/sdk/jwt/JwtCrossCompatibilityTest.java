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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.InputStreamReader;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.virgilsecurity.sdk.FakeDataFactory;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.accessProviders.CallbackJwtProvider;
import com.virgilsecurity.sdk.jwt.accessProviders.CallbackJwtProvider.GetTokenCallback;
import com.virgilsecurity.sdk.jwt.contract.AccessToken;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * @author Andrii Iakovenko
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class JwtCrossCompatibilityTest {

    private static final int TOKEN_EXPIRE_IN_SECONDS = 3;

    private JsonObject sampleJson;
    private FakeDataFactory fake;

    @Mock
    private GetTokenCallback callback;

    @Before
    public void setUp() throws CryptoException {
        this.sampleJson = (JsonObject) new JsonParser().parse(new InputStreamReader(
                this.getClass().getClassLoader().getResourceAsStream("com/virgilsecurity/sdk/test_data.txt")));
        this.fake = new FakeDataFactory();
    }

    @Test
    public void STC_24() throws CryptoException, InterruptedException {
        // Setup CallbackJwtProvider
        CallbackJwtProvider provider = new CallbackJwtProvider(callback);

        // Set getTokenCallback to use JwtGenerator + call counter
        TimeSpan ttl = new TimeSpan(new Date());
        ttl.add(TOKEN_EXPIRE_IN_SECONDS, TimeUnit.SECONDS);
        JwtGenerator generator = new JwtGenerator(this.fake.getApplicationId(), this.fake.getApiPrivateKey(),
                this.fake.getApiPublicKeyId(), ttl, new VirgilAccessTokenSigner());
        when(this.callback.onGetToken())
                .thenReturn(generator.generateToken(this.fake.getIdentity()).stringRepresentation());

        // Prepare contexts
        TokenContext ctx = new TokenContext(fake.getIdentity(), "stc_24", false);
        TokenContext forceReloadCtx = new TokenContext(fake.getIdentity(), "stc_24", true);

        // Call getToken(false)
        AccessToken accessToken1 = provider.getToken(ctx);
        assertNotNull(accessToken1);
        verify(this.callback, times(1)).onGetToken();

        // Call getToken(false)
        AccessToken accessToken2 = provider.getToken(ctx);
        assertNotNull(accessToken2);
        verify(this.callback, times(1)).onGetToken();

        // Wait till token is expired
        Thread.sleep(TOKEN_EXPIRE_IN_SECONDS * 1000);

        // Call getToken(false)
        AccessToken accessToken3 = provider.getToken(ctx);
        assertNotNull(accessToken3);
        verify(this.callback, times(2)).onGetToken();

        // Call getToken(true)
        AccessToken accessToken4 = provider.getToken(forceReloadCtx);
        assertNotNull(accessToken4);
        verify(this.callback, times(3)).onGetToken();
    }

    @Test
    public void STC_28() {
        // Import JWT from string STC-28.jwt
        String token = sampleJson.get("STC-28.jwt").getAsString();
        Jwt jwt = new Jwt(token);

        assertEquals(sampleJson.get("STC-28.jwt_identity").getAsString(), jwt.getBodyContent().getIdentity());
        assertEquals(sampleJson.get("STC-28.jwt_app_id").getAsString(), jwt.getBodyContent().getAppId());
        assertEquals(sampleJson.get("STC-28.jw_issuer").getAsString(), jwt.getBodyContent().getIssuer());
        assertEquals(sampleJson.get("STC-28.jwt_subject").getAsString(), jwt.getBodyContent().getSubject());
        assertEquals(sampleJson.get("STC-28.jwt_additional_data").getAsString(),
                ConvertionUtils.serializeToJson(jwt.getBodyContent().getAdditionalData()));
        assertEquals(sampleJson.get("STC-28.jwt_expires_at").getAsLong(),
                jwt.getBodyContent().getExpiresAt().getTimestamp());
        assertEquals(sampleJson.get("STC-28.jwt_issued_at").getAsLong(),
                jwt.getBodyContent().getIssuedAt().getTime() / 1000);
        assertEquals(sampleJson.get("STC-28.jwt_algorithm").getAsString(), jwt.getHeaderContent().getAlgorithm());
        assertEquals(sampleJson.get("STC-28.jwt_api_key_id").getAsString(), jwt.getHeaderContent().getKeyIdentifier());
        assertEquals(sampleJson.get("STC-28.jwt_content_type").getAsString(), jwt.getHeaderContent().getContentType());
        assertEquals(sampleJson.get("STC-28.jwt_type").getAsString(), jwt.getHeaderContent().getType());
        assertEquals(sampleJson.get("STC-28.jwt_signature_base64").getAsString(),
                ConvertionUtils.toBase64String(jwt.getSignatureData()));

        // Call isExpired()
        assertTrue(jwt.isExpired());

        // Call stringRepresentation()
        assertEquals(token, jwt.stringRepresentation());
    }

    @Test
    @Ignore
    public void STC_29() {

    }

}
