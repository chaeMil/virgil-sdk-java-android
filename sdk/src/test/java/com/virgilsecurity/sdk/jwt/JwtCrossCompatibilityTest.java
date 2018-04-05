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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.virgilsecurity.sdk.FakeDataFactory;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.accessProviders.CallbackJwtProvider;
import com.virgilsecurity.sdk.jwt.accessProviders.CallbackJwtProvider.GetTokenCallback;
import com.virgilsecurity.sdk.jwt.accessProviders.ConstAccessTokenProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import java.io.InputStreamReader;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * @author Andrii Iakovenko
 */
@RunWith(MockitoJUnitRunner.class)
public class JwtCrossCompatibilityTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private static final int TOKEN_EXPIRE_IN_SECONDS = 3;
    private static final String INVALID_TOKEN = "INVALID_TOKEN";
    private static final String TEST_OPERATION = "TEST_OPERATION_STC_24";

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

        // Prepare contexts
        TokenContext ctx = new TokenContext(fake.getIdentity(), TEST_OPERATION, false);

        // Set getTokenCallback to use JwtGenerator + call counter
        TimeSpan ttl = new TimeSpan(new Date());
        ttl.add(TOKEN_EXPIRE_IN_SECONDS, TimeUnit.SECONDS);
        final JwtGenerator generator = new JwtGenerator(fake.getApplicationId(), fake.getApiPrivateKey(),
                fake.getApiPublicKeyId(), ttl, new VirgilAccessTokenSigner());
        when(this.callback.onGetToken(ctx)).thenAnswer(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocationOnMock) throws Throwable {
                return generator.generateToken(fake.getIdentity()).stringRepresentation();
            }
        });

        // Call getToken(false)
        Jwt accessToken1 = (Jwt) provider.getToken(ctx);
        assertNotNull(accessToken1);
        verify(this.callback, times(1)).onGetToken(ctx);

        //For tokens have
        Thread.sleep(2000);

        // Call getToken(false)
        Jwt accessToken2 = (Jwt) provider.getToken(ctx);
        assertNotNull(accessToken2);
        assertFalse("CallbackJwtProvider should always return new token", Objects.equals(accessToken1, accessToken2));
        verify(this.callback, times(2)).onGetToken(ctx);

        //Return invalid token
        when(this.callback.onGetToken(ctx))
                .thenReturn(INVALID_TOKEN);

        expectedException.expect(IllegalArgumentException.class);
        provider.getToken(ctx);
    }

    @Test
    public void STC_37() throws CryptoException, InterruptedException {
        // Setup ConstAccessTokenProvider with fake token
        TimeSpan ttl = new TimeSpan(new Date());
        ttl.add(TOKEN_EXPIRE_IN_SECONDS, TimeUnit.SECONDS);
        JwtGenerator generator = new JwtGenerator(this.fake.getApplicationId(), this.fake.getApiPrivateKey(),
                this.fake.getApiPublicKeyId(), ttl, new VirgilAccessTokenSigner());
        ConstAccessTokenProvider tokenProvider = new ConstAccessTokenProvider(
                generator.generateToken(this.fake.getIdentity()));

        // Prepare contexts
        TokenContext ctx = new TokenContext(fake.getIdentity(), "stc_37", false);
        TokenContext forceReloadCtx = new TokenContext(fake.getIdentity(), "stc_37", true);

        assertFalse("Token should not be expired", ((Jwt) tokenProvider.getToken(ctx)).isExpired());

        // Wait till token is expired
        Thread.sleep(TOKEN_EXPIRE_IN_SECONDS * 1000);

        // Check if tokens are the same regardless of the tokenContext and won't force reload
        Jwt jwtOne = (Jwt) tokenProvider.getToken(ctx);
        assertTrue("Token should be expired", jwtOne.isExpired());
        Jwt jwtTwo = (Jwt) tokenProvider.getToken(ctx);
        assertEquals("ConstAccessTokenProvider always returns the same token regardless of the tokenContext", jwtOne,
                jwtTwo);
        assertTrue("Token should be expired", jwtTwo.isExpired());
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
    public void STC_29() {
        // Import JWT from string STC-29.jwt
        String token = sampleJson.get("STC-29.jwt").getAsString();
        Jwt jwt = new Jwt(token);

        assertEquals(sampleJson.get("STC-29.jwt_identity").getAsString(), jwt.getBodyContent().getIdentity());
        assertEquals(sampleJson.get("STC-29.jwt_app_id").getAsString(), jwt.getBodyContent().getAppId());
        assertEquals(sampleJson.get("STC-29.jw_issuer").getAsString(), jwt.getBodyContent().getIssuer());
        assertEquals(sampleJson.get("STC-29.jwt_subject").getAsString(), jwt.getBodyContent().getSubject());
        assertEquals(sampleJson.get("STC-29.jwt_additional_data").getAsString(),
                ConvertionUtils.serializeToJson(jwt.getBodyContent().getAdditionalData()));
        assertEquals(sampleJson.get("STC-29.jwt_expires_at").getAsLong(),
                jwt.getBodyContent().getExpiresAt().getTimestamp());
        assertEquals(sampleJson.get("STC-29.jwt_issued_at").getAsLong(),
                jwt.getBodyContent().getIssuedAt().getTime() / 1000);
        assertEquals(sampleJson.get("STC-29.jwt_algorithm").getAsString(), jwt.getHeaderContent().getAlgorithm());
        assertEquals(sampleJson.get("STC-29.jwt_api_key_id").getAsString(), jwt.getHeaderContent().getKeyIdentifier());
        assertEquals(sampleJson.get("STC-29.jwt_content_type").getAsString(), jwt.getHeaderContent().getContentType());
        assertEquals(sampleJson.get("STC-29.jwt_type").getAsString(), jwt.getHeaderContent().getType());
        assertEquals(sampleJson.get("STC-29.jwt_signature_base64").getAsString(),
                ConvertionUtils.toBase64String(jwt.getSignatureData()));

        // Call isExpired()
        assertFalse(jwt.isExpired());

        // Call stringRepresentation()
        assertEquals(token, jwt.stringRepresentation());
    }

}
