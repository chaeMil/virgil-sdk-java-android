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
package com.virgilsecurity.sdk.client;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import com.virgilsecurity.sdk.client.exceptions.AuthServiceException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.client.model.auth.AcknowledgeRequest;
import com.virgilsecurity.sdk.client.model.auth.AcknowledgeResponse;
import com.virgilsecurity.sdk.client.model.auth.GetChallengeMessageRequest;
import com.virgilsecurity.sdk.client.model.auth.GetChallengeMessageResponse;
import com.virgilsecurity.sdk.client.model.auth.ObtainAccessTokenRequest;
import com.virgilsecurity.sdk.client.model.auth.ObtainAccessTokenResponse;
import com.virgilsecurity.sdk.client.model.auth.RefreshAccessTokenRequest;
import com.virgilsecurity.sdk.client.model.auth.RefreshAccessTokenResponse;
import com.virgilsecurity.sdk.client.model.auth.VerifyRequest;
import com.virgilsecurity.sdk.client.model.auth.VerifyResponse;
import com.virgilsecurity.sdk.client.model.dto.ErrorResponse;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StreamUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilAuthClient extends ClientBase {

    /**
     * Create new instance of {@link VirgilAuthClient}.
     */
    public VirgilAuthClient(VirgilClientContext context) {
        super(context);
    }

    /**
     * @param virgilCardId
     * @return
     */
    public GetChallengeMessageResponse getChallengeMessage(String virgilCardId) {
        GetChallengeMessageResponse response = doRequest(context.getAuthServiceURL(),
                "/v4/authorization-grant/actions/get-challenge-message", "POST",
                new GetChallengeMessageRequest(virgilCardId), GetChallengeMessageResponse.class);

        return response;
    }

    /**
     * @param challengeMessage
     * @return
     */
    public String acknowledge(GetChallengeMessageResponse challengeMessage) {
        return acknowledge(challengeMessage.getAuthorizationGrantId(), challengeMessage.getEncryptedMessage());
    }

    /**
     * @param encryptedMessage
     * @return
     */
    public String acknowledge(String authorizationGrantId, String encryptedMessage) {
        String spec = new StringBuilder("/v4/authorization-grant/").append(authorizationGrantId)
                .append("/actions/acknowledge").toString();
        AcknowledgeResponse response = doRequest(context.getAuthServiceURL(), spec, "POST",
                new AcknowledgeRequest(encryptedMessage), AcknowledgeResponse.class);
        return response.getCode();
    }

    public ObtainAccessTokenResponse obtainAccessToken(String code) {
        ObtainAccessTokenResponse response = doRequest(context.getAuthServiceURL(),
                "/v4/authorization/actions/obtain-access-token", "POST", new ObtainAccessTokenRequest(code),
                ObtainAccessTokenResponse.class);

        return response;
    }

    public RefreshAccessTokenResponse refreshAccessToken(String refreshToken) {
        RefreshAccessTokenResponse response = doRequest(context.getAuthServiceURL(),
                "/v4/authorization/actions/refresh-access-token", "POST", new RefreshAccessTokenRequest(refreshToken),
                RefreshAccessTokenResponse.class);

        return response;
    }

    public String verify(String accessToken) {
        VerifyResponse response = doRequest(context.getAuthServiceURL(), "/v4/authorization/actions/verify", "POST",
                new VerifyRequest(accessToken), VerifyResponse.class);

        return response.getVirgilCardId();
    }

    protected <T> T doRequest(URL context, String spec, String method, Object body, Class<T> clazz) {
        String bodyStr = ConvertionUtils.getGson().toJson(body);
        try {
            return execute(new URL(context, spec), method, new ByteArrayInputStream(ConvertionUtils.toBytes(bodyStr)),
                    clazz);
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthServiceException(e);
        }
    }

    protected <T> T execute(URL url, String method, InputStream inputStream, Class<T> clazz) {
        try {
            HttpURLConnection urlConnection = createConnection(url, method);
            if (inputStream != null) {
                StreamUtils.copyStream(inputStream, urlConnection.getOutputStream());
            }
            try {
                if (urlConnection.getResponseCode() >= HttpURLConnection.HTTP_BAD_REQUEST) {
                    // Get error code from request
                    try (InputStream in = new BufferedInputStream(urlConnection.getErrorStream())) {
                        String body = ConvertionUtils.toString(in);
                        if (!StringUtils.isBlank(body)) {
                            ErrorResponse error = ConvertionUtils.getGson().fromJson(body, ErrorResponse.class);
                            throw new AuthServiceException(error.getCode());
                        }
                    }
                    if (urlConnection.getResponseCode() == HttpURLConnection.HTTP_NOT_FOUND) {
                        return null;
                    }
                    throw new AuthServiceException();
                } else if (clazz.isAssignableFrom(Void.class)) {
                    return null;
                } else {
                    try (InputStream instream = new BufferedInputStream(urlConnection.getInputStream())) {
                        String body = ConvertionUtils.toString(instream);
                        return ConvertionUtils.getGson().fromJson(body, clazz);
                    }
                }
            } finally {
                urlConnection.disconnect();
            }
        } catch (IOException e) {
            throw new AuthServiceException(e);
        }
    }
}
