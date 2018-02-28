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

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.virgilsecurity.sdk.client.exceptions.CardValidationException;
import com.virgilsecurity.sdk.client.model.CardInfoModel;
import com.virgilsecurity.sdk.client.model.CardMetaModel;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.client.model.CardScope;
import com.virgilsecurity.sdk.client.model.IdentityType;
import com.virgilsecurity.sdk.client.model.RevocationReason;
import com.virgilsecurity.sdk.client.model.dto.PublishCardSnapshotModel;
import com.virgilsecurity.sdk.client.model.dto.SearchCriteria;
import com.virgilsecurity.sdk.client.requests.RevokeCardRequest;
import com.virgilsecurity.sdk.client.requests.RevokeGlobalCardRequest;
import com.virgilsecurity.sdk.crypto.Fingerprint;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.exception.EmptyArgumentException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * This class provides a list of methods to manage the {@link VirgilCard} entities.
 * 
 * @author Andrii Iakovenko
 *
 */
public class VirgilCardManager implements CardManager {

    private VirgilApiContext context;

    /**
     * Create new instance of {@link VirgilCardManager}.
     * 
     * @param context
     *            The context.
     */
    public VirgilCardManager(VirgilApiContext context) {
        super();
        this.context = context;
    }

    /**
     * Creates a new {@link VirgilCard} that is representing user's Public key and information about identity. This card
     * has to be published to the Virgil's services.
     * 
     * @param identity
     *            The user's identity.
     * @param ownerKey
     *            The owner's {@link VirgilKey}.
     * @return A new instance of {@link VirgilCard} class, that is representing user's Public key.
     */
    public VirgilCard create(String identity, VirgilKey ownerKey) {
        return create(identity, ownerKey, "unknown");
    }

    /**
     * Creates a new {@link VirgilCard} that is representing user's Public key and information about identity. This card
     * has to be published to the Virgil's services.
     * 
     * @param identity
     *            The user's identity.
     * @param ownerKey
     *            The owner's {@link VirgilKey}.
     * @param identityType
     *            Type of the identity.
     * @return A new instance of {@link VirgilCard} class, that is representing user's Public key.
     */
    public VirgilCard create(String identity, VirgilKey ownerKey, String identityType) {
        return create(identity, ownerKey, identityType, null);
    }

    /**
     * Creates a new {@link VirgilCard} that is representing user's Public key and information about identity. This card
     * has to be published to the Virgil's services.
     * 
     * @param identity
     *            The user's identity.
     * @param ownerKey
     *            The owner's {@link VirgilKey}.
     * @param identityType
     *            Type of the identity.
     * @param customFields
     *            The custom fields.
     * @return A new instance of {@link VirgilCard} class, that is representing user's Public key.
     */
    public VirgilCard create(String identity, VirgilKey ownerKey, String identityType,
            Map<String, String> customFields) {
        CardModel cardModel = this.buildCardModel(identity, ownerKey, identityType, customFields,
                CardScope.APPLICATION);

        return new VirgilCard(this.context, cardModel);
    }

    /**
     * Creates a new global {@link VirgilCard} that is representing user's Public key and information about identity.
     * 
     * @param identity
     *            The user's identity value.
     * @param ownerKey
     *            The owner's {@link VirgilKey}.
     * @param identityType
     *            Type of the identity.
     * @return A new instance of {@link VirgilCard} class, that is representing user's Public key.
     */
    public VirgilCard createGlobal(String identity, VirgilKey ownerKey, IdentityType identityType) {
        return createGlobal(identity, ownerKey, identityType, null);
    }

    /**
     * Creates a new global {@link VirgilCard} that is representing user's Public key and information about identity.
     * 
     * @param identity
     *            The user's identity value.
     * @param ownerKey
     *            The owner's {@link VirgilKey}.
     * @param identityType
     *            Type of the identity.
     * @param customFields
     *            The custom fields.
     * @return A new instance of {@link VirgilCard} class, that is representing user's Public key.
     */
    public VirgilCard createGlobal(String identity, VirgilKey ownerKey, IdentityType identityType,
            Map<String, String> customFields) {

        CardModel cardModel = this.buildCardModel(identity, ownerKey, identityType.getValue(), customFields,
                CardScope.GLOBAL);

        return new VirgilCard(this.context, cardModel);
    }

    /**
     * Finds a {@link VirgilCard}s by specified identities in application scope.
     * 
     * @param identities
     *            The list of identities.
     * @return A collection of found {@link VirgilCard}s.
     * @throws CardValidationException
     */
    public VirgilCards find(String... identities) throws CardValidationException {
        if (identities == null || identities.length == 0) {
            throw new EmptyArgumentException("identities");
        }

        return this.find(null, Arrays.asList(identities));
    }

    /**
     * Finds a {@link VirgilCard}s by specified identities in application scope.
     * 
     * @param identities
     *            The list of identities.
     * @return A collection of found {@link VirgilCard}s.
     * @throws CardValidationException
     */
    public VirgilCards find(Collection<String> identities) throws CardValidationException {
        if (identities == null || identities.isEmpty()) {
            throw new EmptyArgumentException("identities");
        }

        return this.find(null, identities);
    }

    /**
     * Finds {@link VirgilCard}s by specified identities and type in application scope.
     * 
     * @param identityType
     *            Type of identity.
     * @param identities
     *            The list of sought identities.
     * @return A new collection with found {@link VirgilCard}.
     * @throws CardValidationException
     */
    public VirgilCards find(String identityType, Collection<String> identities) throws CardValidationException {
        if (identities == null || identities.isEmpty()) {
            throw new EmptyArgumentException("identities");
        }

        SearchCriteria criteria = SearchCriteria.byIdentities(identities);
        criteria.setIdentityType(identityType);
        criteria.setScope(CardScope.APPLICATION);

        VirgilCards cards = this.searchByCriteria(criteria);
        return cards;
    }

    /**
     * Finds {@link VirgilCard}s by specified identities and type in global scope.
     * 
     * @param identities
     *            The sought identities.
     * @return A new collection with found {@link VirgilCard}s.
     * @throws CardValidationException
     */
    public VirgilCards findGlobal(String identities) throws CardValidationException {
        return this.findGlobal(Arrays.asList(identities));
    }

    /**
     * Finds {@link VirgilCard}s by specified identities and type in global scope.
     * 
     * @param identities
     *            The list of sought identities.
     * @return A new collection with found {@link VirgilCard}s.
     * @throws CardValidationException
     */
    public VirgilCards findGlobal(Collection<String> identities) throws CardValidationException {
        if (identities == null || identities.isEmpty()) {
            throw new EmptyArgumentException("identities");
        }

        SearchCriteria criteria = SearchCriteria.byIdentities(identities);
        criteria.setScope(CardScope.GLOBAL);

        VirgilCards cards = this.searchByCriteria(criteria);
        return cards;
    }

    /**
     * Finds {@link VirgilCard}s by specified identities and type in global scope.
     * 
     * @param identityType
     *            Type of identity.
     * @param identities
     *            The list of sought identities.
     * @return A new collection with found {@link VirgilCard}s.
     * @throws CardValidationException
     */
    public VirgilCards findGlobal(IdentityType identityType, Collection<String> identities)
            throws CardValidationException {

        if (identities == null || identities.isEmpty()) {
            throw new EmptyArgumentException("identities");
        }

        SearchCriteria criteria = SearchCriteria.byIdentities(identities);
        criteria.setIdentityType(identityType.getValue());
        criteria.setScope(CardScope.GLOBAL);

        VirgilCards cards = this.searchByCriteria(criteria);
        return cards;
    }

    /**
     * Imports a {@link VirgilCard} from specified buffer.
     * 
     * @param exportedCard
     *            A Card in string representation.
     * @return An instance of {@link VirgilCard}.
     */
    public VirgilCard importCard(String exportedCard) {
        VirgilBuffer bufferCard = VirgilBuffer.from(exportedCard, StringEncoding.Base64);
        CardModel importedCardModel = ConvertionUtils.getGson().fromJson(bufferCard.toString(), CardModel.class);

        return new VirgilCard(this.context, importedCardModel);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.highlevel.CardManager#importCard(com.virgilsecurity.sdk.client.model.CardModel)
     */
    public VirgilCard importCard(CardModel cardModel) {
        return new VirgilCard(this.context, cardModel);
    }

    /**
     * Publishes a {@link VirgilCard} into application Virgil Services scope.
     * 
     * @param card
     *            The Card to be published.
     * @throws CryptoException
     */
    public void publish(VirgilCard card) throws CryptoException {
        card.publish();
    }

    /**
     * Publishes a {@link VirgilCard} into global Virgil Services scope.
     * 
     * @param card
     *            The Card to be published.
     * @param token
     *            The identity validation token.
     */
    public void publishGlobal(VirgilCard card, IdentityValidationToken token) {
        card.publishAsGlobal(token);
    }

    /**
     * Revokes a {@link VirgilCard} from Virgil Services.
     * 
     * @param card
     *            The card to be revoked.
     * @throws CryptoException
     */
    public void revoke(VirgilCard card) throws CryptoException {
        RevokeCardRequest revokeRequest = new RevokeCardRequest(card.getId(), RevocationReason.UNSPECIFIED);

        String appId = this.context.getCredentials().getAppId();
        PrivateKey appKey = this.context.getCredentials().getAppKey(this.context.getCrypto());

        Fingerprint fingerprint = this.context.getCrypto().calculateFingerprint(revokeRequest.getSnapshot());
        byte[] signature = this.context.getCrypto().sign(fingerprint.getValue(), appKey);

        revokeRequest.appendSignature(appId, signature);

        this.context.getClient().revokeCard(revokeRequest);
    }

    /**
     * Revokes a global {@link VirgilCard} from Virgil Security services.
     * 
     * @param card
     *            The Card to be revoked.
     * @param key
     *            The Key associated with the revoking Card.
     * @param identityToken
     *            The identity token.
     */
    public void revokeGlobal(VirgilCard card, VirgilKey key, IdentityValidationToken identityToken) {
        RevokeGlobalCardRequest revokeRequest = new RevokeGlobalCardRequest(card.getId(), RevocationReason.UNSPECIFIED,
                identityToken.getValue());

        Fingerprint fingerprint = this.context.getCrypto().calculateFingerprint(revokeRequest.getSnapshot());
        VirgilBuffer signature = key.sign(VirgilBuffer.from(fingerprint.getValue()));

        revokeRequest.appendSignature(card.getId(), signature.getBytes());

        this.context.getClient().revokeGlobalCard(revokeRequest);
    }

    /**
     * Gets a {@link VirgilCard} from Virgil Security services by specified Card ID.
     * 
     * @param cardId
     *            The unique string that identifies the Card within Virgil Security services.
     * @return An instance of {@link VirgilCard}.
     */
    public VirgilCard get(String cardId) {
        CardModel cardModel = this.context.getClient().getCard(cardId);
        if (cardModel == null) {
            return null;
        }
        VirgilCard card = new VirgilCard(this.context, cardModel);

        return card;
    }

    private VirgilCards searchByCriteria(SearchCriteria criteria) throws CardValidationException {
        List<CardModel> cardModels = this.context.getClient().searchCards(criteria);
        VirgilCards cards = new VirgilCards(this.context);
        for (CardModel cardModel : cardModels) {
            cards.add(new VirgilCard(this.context, cardModel));
        }
        return cards;
    }

    private CardModel buildCardModel(String identity, VirgilKey ownerKey, String identityType,
            Map<String, String> customFields, CardScope scope) {
        PublishCardSnapshotModel cardSnapshotModel = new PublishCardSnapshotModel();
        cardSnapshotModel.setIdentity(identity);
        cardSnapshotModel.setIdentityType(identityType);
        cardSnapshotModel.setPublicKeyData(ownerKey.exportPublicKey().getBytes());
        cardSnapshotModel.setScope(scope);
        cardSnapshotModel.setData(customFields);

        CardInfoModel info = new CardInfoModel();
        info.setDevice(this.context.getDeviceManager().getSystemName());
        info.setDeviceName(this.context.getDeviceManager().getDeviceName());
        cardSnapshotModel.setInfo(info);

        byte[] snapshot = ConvertionUtils.captureSnapshot(cardSnapshotModel);

        Fingerprint snapshotFingerprint = this.context.getCrypto().calculateFingerprint(snapshot);
        String cardId = snapshotFingerprint.toHex();
        VirgilBuffer selfSignature = ownerKey.sign(VirgilBuffer.from(snapshotFingerprint.getValue()));

        Map<String, byte[]> signatures = new HashMap<>();
        signatures.put(cardId, selfSignature.getBytes());

        CardModel cardModel = new CardModel(cardSnapshotModel);
        cardModel.setId(cardId);
        cardModel.setSnapshot(snapshot);

        CardMetaModel meta = new CardMetaModel();
        meta.setSignatures(signatures);
        cardModel.setMeta(meta);

        return cardModel;
    }
}
