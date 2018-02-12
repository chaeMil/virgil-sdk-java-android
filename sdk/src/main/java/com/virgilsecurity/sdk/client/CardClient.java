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
package com.virgilsecurity.sdk.client;

import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardIsOutdatedException;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardServiceException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.exception.EmptyArgumentException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.Tuple;


/**
 * The {@link CardClient} class represents a Virgil Security service
 * client and contains all methods for interaction with server.
 */
public class CardClient {

    private URL serviceUrl;
    private HttpClient httpClient;

    /**
     * Create a new instance of {@code CardClient}
     */
    public CardClient() {
        this("https://api.virgilsecurity.com/card/v5/");
    }

    /**
     * Create a new instance of {@code CardClient}
     *
     * @param serviceUrl
     *         the service url to fire requests to
     */
    public CardClient(String serviceUrl) {
        try {
            this.serviceUrl = new URL(serviceUrl);
        } catch (MalformedURLException e) {
            e.printStackTrace();
            throw new IllegalArgumentException("CardClient -> 'serviceUrl' has wrong format");
        }
        httpClient = new HttpClient();
    }

    /**
     * Create a new instance of {@code CardClient}
     *
     * @param serviceUrl
     *         the service url to fire requests to
     */
    public CardClient(URL serviceUrl) {
        this.serviceUrl = serviceUrl;
        httpClient = new HttpClient();
    }

    /**
     * Get card from Virgil Services by specified identifier.
     *
     * @param cardId
     *         the card identifier.
     * @param token
     *         token to authorize the request.
     * @return the card loaded from Virgil Cards service.
     */
    public Tuple<RawSignedModel, Boolean> getCard(String cardId,
                                                  String token) throws VirgilServiceException {
        try {
            URL url = new URL(serviceUrl, cardId);

            return new Tuple<>(httpClient.execute(url,
                                                  "GET",
                                                  token,
                                                  null,
                                                  RawSignedModel.class), false);
        } catch (VirgilCardIsOutdatedException e) {
            return new Tuple<>(e.getCardModel(),
                               true); // FIXME: 1/30/18 temporary workaround with 403 for outdated card
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Publishes card in Virgil Cards service.
     *
     * @param rawCard
     *         raw signed model of card to be published.
     * @param token
     *         token to authorize the request.
     * @return the {@link RawSignedModel} of the Card that is published to Virgil Cards service.
     * @throws VirgilServiceException
     *         if an error occurred while publishing Card.
     */
    public RawSignedModel publishCard(RawSignedModel rawCard, String token) throws VirgilServiceException {
        try {
            URL url = serviceUrl;
            String body = rawCard.exportAsJson();

            return httpClient.execute(url,
                                      "POST",
                                      token,
                                      new ByteArrayInputStream(ConvertionUtils.toBytes(body)),
                                      RawSignedModel.class);
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Search cards Virgil Services by specified identity.
     *
     * @param identity
     *         the identity for search.
     * @param token
     *         token to authorize the request.
     * @return A list of found cards.
     */
    public List<RawSignedModel> searchCards(String identity, String token) throws VirgilServiceException {
        if (identity == null)
            throw new NullArgumentException("CardClient -> 'identity' should not be null");

        if (identity.isEmpty())
            throw new EmptyArgumentException("CardClient -> 'identity' should not be empty");

        try {
            URL url = new URL(serviceUrl, "actions/search");
            String body = "{\"identity\":\"" + identity + "\"}";

            RawSignedModel[] cardModels =
                    httpClient.execute(url,
                                       "POST",
                                       token,
                                       new ByteArrayInputStream(ConvertionUtils.toBytes(body)),
                                       RawSignedModel[].class);

            return Arrays.asList(cardModels);
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Gets http client that is used to fire requests.
     *
     * @return the http client
     */
    public HttpClient getHttpClient() {
        return httpClient;
    }

    /**
     * Sets http client that is used to fire requests.
     *
     * @param httpClient
     *         the http client
     */
    public void setHttpClient(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Gets service url that is used to fire requests to.
     *
     * @return the service url
     */
    public URL getServiceUrl() {
        return serviceUrl;
    }
}
