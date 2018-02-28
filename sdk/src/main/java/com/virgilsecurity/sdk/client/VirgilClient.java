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

import java.io.ByteArrayInputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import com.virgilsecurity.sdk.client.exceptions.CardValidationException;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardServiceException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.client.model.CardScope;
import com.virgilsecurity.sdk.client.model.dto.IdentityConfirmationRequestModel;
import com.virgilsecurity.sdk.client.model.dto.IdentityConfirmationResponseModel;
import com.virgilsecurity.sdk.client.model.dto.IdentityValidationRequestModel;
import com.virgilsecurity.sdk.client.model.dto.IdentityVerificationRequestModel;
import com.virgilsecurity.sdk.client.model.dto.IdentityVerificationResponseModel;
import com.virgilsecurity.sdk.client.model.dto.RevokeCardSnapshotModel;
import com.virgilsecurity.sdk.client.model.dto.SearchCriteria;
import com.virgilsecurity.sdk.client.model.dto.SearchRequest;
import com.virgilsecurity.sdk.client.model.dto.SignableRequestModel;
import com.virgilsecurity.sdk.client.model.dto.Token;
import com.virgilsecurity.sdk.client.requests.PublishCardRequest;
import com.virgilsecurity.sdk.client.requests.PublishGlobalCardRequest;
import com.virgilsecurity.sdk.client.requests.RevokeCardRequest;
import com.virgilsecurity.sdk.client.requests.RevokeGlobalCardRequest;
import com.virgilsecurity.sdk.exception.EmptyArgumentException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilClient extends ClientBase {

    private CardValidator cardValidator;

    /**
     * Create a new instance of {@code VirgilClient}
     *
     * @param accessToken
     *            the access token.
     */
    public VirgilClient(String accessToken) {
        super(new VirgilClientContext(accessToken));
    }

    /**
     * Create a new instance of {@code VirgilClient}
     *
     * @param context
     *            the virgil client context.
     */
    public VirgilClient(VirgilClientContext context) {
        super(context);
    }

    /**
     * Sends the request for identity verification, that's will be processed depending of specified type.
     * 
     * @param identity
     *            An unique string that represents identity.
     * @param identityType
     *            The type of identity.
     * @return action id.
     * 
     * @see #confirmIdentity(String, String, Token)
     */
    public String verifyIdentity(String identity, String identityType) {
        return verifyIdentity(identity, identityType, null);
    }

    /**
     * Sends the request for identity verification, that's will be processed depending of specified type.
     * 
     * @param identity
     *            An unique string that represents identity.
     * @param identityType
     *            The type of identity.
     * @param extraFields
     *            The extra fields.
     * @return action id.
     * 
     * @see #confirmIdentity(String, String, Token)
     */
    public String verifyIdentity(String identity, String identityType, Map<String, String> extraFields) {
        IdentityVerificationRequestModel requestModel = new IdentityVerificationRequestModel(identity, identityType,
                extraFields);

        try {
            URL url = new URL(context.getIdentityServiceURL(), "v1/verify");

            String body = ConvertionUtils.getGson().toJson(requestModel);

            IdentityVerificationResponseModel responseModel = execute(url, "POST",
                    new ByteArrayInputStream(ConvertionUtils.toBytes(body)), IdentityVerificationResponseModel.class);
            return responseModel.getActionId();
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Confirms the identity from the verify step to obtain an identity confirmation token.
     * 
     * @param actionId
     *            the action identifier.
     * @param confirmationCode
     *            the confirmation code.
     * @return The validation token.
     */
    public String confirmIdentity(String actionId, String confirmationCode) {
        return confirmIdentity(actionId, confirmationCode, new Token(3600, 1));
    }

    /**
     * Confirms the identity from the verify step to obtain an identity confirmation token.
     * 
     * @param actionId
     *            the action identifier.
     * @param confirmationCode
     *            the confirmation code.
     * @param confirmationToken
     *            the confirmation token.
     * @return The validation token.
     */
    public String confirmIdentity(String actionId, String confirmationCode, Token confirmationToken) {
        IdentityConfirmationRequestModel requestModel = new IdentityConfirmationRequestModel(actionId, confirmationCode,
                confirmationToken);

        try {
            URL url = new URL(context.getIdentityServiceURL(), "v1/confirm");

            String body = ConvertionUtils.getGson().toJson(requestModel);

            IdentityConfirmationResponseModel responseModel = execute(url, "POST",
                    new ByteArrayInputStream(ConvertionUtils.toBytes(body)), IdentityConfirmationResponseModel.class);
            return responseModel.getValidationToken();
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Checks validated token.
     * 
     * @param identity
     *            The value of identity.
     * @param identityType
     *            The type of identity.
     * @param validationToken
     *            The validation token.
     * @return {@code true} if validation token is valid.
     */
    public boolean isIdentityValid(String identity, String identityType, String validationToken) {
        IdentityValidationRequestModel requestModel = new IdentityValidationRequestModel(identity, identityType,
                validationToken);

        try {
            URL url = new URL(context.getIdentityServiceURL(), "v1/validate");

            String body = ConvertionUtils.getGson().toJson(requestModel);

            execute(url, "POST", new ByteArrayInputStream(ConvertionUtils.toBytes(body)), Void.class);
            return true;
        } catch (VirgilServiceException e) {
            return false;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Register a new card.
     * 
     * @param request
     *            the create card request.
     * @return the created card.
     * @throws VirgilServiceException
     *             if an error occurred.
     */
    public CardModel publishCard(PublishCardRequest request) throws VirgilServiceException {
        try {
            URL url = new URL(context.getCardsServiceURL(), "/v4/card");

            String body = ConvertionUtils.getGson().toJson(request.getRequestModel());

            CardModel cardModel = execute(url, "POST", new ByteArrayInputStream(ConvertionUtils.toBytes(body)),
                    CardModel.class);

            validateCards(Arrays.asList(cardModel));

            return cardModel;
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Register a new card.
     * 
     * @param request
     *            The create card request.
     * @return The created card.
     * @throws VirgilServiceException
     *             if an error occurred.
     */
    public CardModel publishGlobalCard(PublishGlobalCardRequest request) {
        try {
            URL url = new URL(context.getRaServiceURL(), "/v1/card");

            SignableRequestModel requestModel = request.getRequestModel();

            String body = ConvertionUtils.getGson().toJson(requestModel);

            CardModel cardModel = execute(url, "POST", new ByteArrayInputStream(ConvertionUtils.toBytes(body)),
                    CardModel.class);

            validateCards(Arrays.asList(cardModel));

            return cardModel;
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Get card by identifier.
     * 
     * @param cardId
     *            the card identifier.
     * @return the card.
     */
    public CardModel getCard(String cardId) {
        try {
            URL url = new URL(context.getReadOnlyCardsServiceURL(), "/v4/card/" + cardId);

            CardModel cardModel = execute(url, "GET", null, CardModel.class);

            validateCards(Arrays.asList(cardModel));

            return cardModel;

        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Revoke existing card.
     * 
     * @param request
     *            the revoke card request.
     */
    public void revokeCard(RevokeCardRequest request) {
        try {
            RevokeCardSnapshotModel snapshotModel = request.extractSnapshotModel();

            URL url = new URL(context.getCardsServiceURL(), "/v4/card/" + snapshotModel.getCardId());
            String body = ConvertionUtils.getGson().toJson(request.getRequestModel());

            execute(url, "DELETE", new ByteArrayInputStream(ConvertionUtils.toBytes(body)), Void.class);
        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Revoke existing card.
     * 
     * @param request
     *            The revoke card request.
     */
    public void revokeGlobalCard(RevokeGlobalCardRequest request) {
        try {
            RevokeCardSnapshotModel snapshotModel = request.extractSnapshotModel();
            URL url = new URL(context.getRaServiceURL(), "/v1/card/" + snapshotModel.getCardId());

            String body = ConvertionUtils.getGson().toJson(request.getRequestModel());

            execute(url, "DELETE", new ByteArrayInputStream(ConvertionUtils.toBytes(body)), Void.class);

        } catch (VirgilServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    /**
     * Search cards by criteria.
     * 
     * @param criteria
     *            the criteria for search.
     * @return the found cards list.
     * @throws CardValidationException
     */
    public List<CardModel> searchCards(SearchCriteria criteria) throws CardValidationException {
        if (criteria == null) {
            throw new NullArgumentException("criteria");
        }

        if (criteria.getIdentities().isEmpty()) {
            throw new EmptyArgumentException("criteria");
        }

        SearchRequest request = new SearchRequest();

        request.setIdentities(criteria.getIdentities());

        if (!StringUtils.isBlank(criteria.getIdentityType())) {
            request.setIdentityType(criteria.getIdentityType());
        }

        if (criteria.getScope() == CardScope.GLOBAL) {
            request.setScope(criteria.getScope());
        }

        try {
            URL url = new URL(context.getReadOnlyCardsServiceURL(), "/v4/card/actions/search");
            String body = ConvertionUtils.getGson().toJson(request);

            CardModel[] cardModels = execute(url, "POST", new ByteArrayInputStream(ConvertionUtils.toBytes(body)),
                    CardModel[].class);

            if (cardModels != null) {
                List<CardModel> cards = Arrays.asList(cardModels);
                validateCards(cards);

                return cards;
            } else {
                return new ArrayList<>();
            }
        } catch (VirgilServiceException e) {
            throw e;
        } catch (CardValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new VirgilCardServiceException(e);
        }
    }

    private void validateCards(Collection<CardModel> cards) throws CardValidationException {
        if (this.cardValidator == null) {
            return;
        }
        List<CardModel> invalidCards = new ArrayList<>();

        for (CardModel card : cards) {
            if (!this.cardValidator.validate(card)) {
                invalidCards.add(card);
            }
        }

        if (!invalidCards.isEmpty()) {
            throw new CardValidationException(invalidCards);
        }
    }

    /**
     * Sets the card validator.
     * 
     * @param cardValidator
     *            the cardValidator to set
     */
    public void setCardValidator(CardValidator cardValidator) {
        if (cardValidator == null) {
            throw new NullArgumentException("cardValidator");
        }

        this.cardValidator = cardValidator;
    }

}
