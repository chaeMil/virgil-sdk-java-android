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

import com.virgilsecurity.sdk.client.exceptions.VirgilCardServiceException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.client.model.dto.ErrorResponse;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StreamUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class ClientBase {

    protected VirgilClientContext context;

    /**
     * Create new instance of {@link ClientBase}.
     * 
     * @param context
     *            the VirgilClient context.
     */
    public ClientBase(VirgilClientContext context) {
        super();
        this.context = context;
    }

    /**
     * Create and configure http connection.
     * 
     * @param url
     *            The URL.
     * @param method
     *            The HTTP method.
     * @return The connection.
     * @throws IOException
     */
    protected HttpURLConnection createConnection(URL url, String method) throws IOException {
        HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
        urlConnection.setRequestMethod(method);
        urlConnection.setUseCaches(false);

        switch (method) {
        case "DELETE":
        case "POST":
        case "PUT":
        case "PATCH":
            urlConnection.setDoOutput(true);
            urlConnection.setChunkedStreamingMode(0);
            break;
        default:
        }
        String accessToken = context.getAccessToken();
        if (!StringUtils.isBlank(accessToken)) {
            urlConnection.setRequestProperty("Authorization", "VIRGIL " + context.getAccessToken());
        }
        urlConnection.setRequestProperty("Content-Type", "application/json; charset=utf-8");

        return urlConnection;
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
                            throw new VirgilCardServiceException(error.getCode());
                        }
                    }
                    if (urlConnection.getResponseCode() == HttpURLConnection.HTTP_NOT_FOUND) {
                        return null;
                    }
                    throw new VirgilCardServiceException();
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
            throw new VirgilCardServiceException(e);
        }
    }

}
