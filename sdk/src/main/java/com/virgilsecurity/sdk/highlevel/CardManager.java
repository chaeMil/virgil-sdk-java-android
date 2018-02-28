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

import java.util.Collection;
import java.util.Map;

import com.virgilsecurity.sdk.client.exceptions.CardValidationException;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.client.model.IdentityType;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

/**
 * The {@linkplain CardManager} interface defines a list of methods to manage the {@link VirgilCard}s.
 * 
 * @author Andrii Iakovenko
 *
 */
public interface CardManager {

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
    VirgilCard create(String identity, VirgilKey ownerKey);

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
    VirgilCard create(String identity, VirgilKey ownerKey, String identityType);

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
    VirgilCard create(String identity, VirgilKey ownerKey, String identityType, Map<String, String> customFields);

    /**
     * Creates a new global {@link VirgilCard} that is representing user's Public key and information about identity.
     * 
     * @param identity
     *            The user's identity.
     * @param ownerKey
     *            The owner's {@link VirgilKey}.
     * @param identityType
     *            Type of the identity.
     * @return A new instance of {@link VirgilCard} class, that is representing user's Public key.
     */
    VirgilCard createGlobal(String identity, VirgilKey ownerKey, IdentityType identityType);

    /**
     * Creates a new global {@link VirgilCard} that is representing user's Public key and information about identity.
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
    VirgilCard createGlobal(String identity, VirgilKey ownerKey, IdentityType identityType,
            Map<String, String> customFields);

    /**
     * Finds a {@link VirgilCard}s by specified identities in application scope.
     * 
     * @param identities
     *            The list of identities.
     * @return A list of found {@link VirgilCard}s.
     * @throws CardValidationException
     */
    VirgilCards find(String... identities) throws CardValidationException;

    /**
     * Finds a {@link VirgilCard}s by specified identities in application scope.
     * 
     * @param identities
     *            The list of identities.
     * @return A list of found {@link VirgilCard}s.
     * @throws CardValidationException
     */
    VirgilCards find(Collection<String> identities) throws CardValidationException;

    /**
     * Finds {@link VirgilCard}s by specified identities and type in application scope.
     * 
     * @param identityType
     *            Type of identity.
     * @param identities
     *            The list of sought identities.
     * @return A list of found {@link VirgilCard}s.
     * @throws CardValidationException
     */
    VirgilCards find(String identityType, Collection<String> identities) throws CardValidationException;

    /**
     * Finds a {@link VirgilCard}s by by specified identities and type in global scope.
     * 
     * @param identities
     *            The sought identities.
     * @return A list of found {@link VirgilCard}s.
     * @throws CardValidationException
     */
    VirgilCards findGlobal(String identities) throws CardValidationException;

    /**
     * Finds a {@link VirgilCard}s by by specified identities and type in global scope.
     * 
     * @param identities
     *            The list of identities.
     * @return A list of found {@link VirgilCard}s.
     * @throws CardValidationException
     */
    VirgilCards findGlobal(Collection<String> identities) throws CardValidationException;

    /**
     * Imports a {@link VirgilCard} from specified buffer.
     * 
     * @param exportedCard
     *            The Card in string representation.
     * @return An instance of {@link VirgilCard}.
     */
    VirgilCard importCard(String exportedCard);

    /**
     * Imports a {@link VirgilCard} from specified buffer.
     * 
     * @param cardModel
     *            The Card model.
     * @return An instance of {@link VirgilCard}.
     */
    VirgilCard importCard(CardModel cardModel);

    /**
     * Publishes a {@link VirgilCard} into global Virgil Services scope.
     * 
     * @param card
     *            The Card to be published.
     * @param token
     *            The identity validation token.
     */
    void publishGlobal(VirgilCard card, IdentityValidationToken token);

    /**
     * Publishes a {@linkplain VirgilCard} into application Virgil Services scope.
     * 
     * @param card
     *            The Card to be published.
     * @throws CryptoException
     */
    void publish(VirgilCard card) throws CryptoException;

    /**
     * Revokes a {@link VirgilCard} from Virgil Services.
     * 
     * @param card
     *            The card to be revoked.
     * @throws CryptoException
     */
    void revoke(VirgilCard card) throws CryptoException;

    /**
     * Revokes a global {@link VirgilCard} from Virgil Security services.
     * 
     * @param card
     *            The Card to be revoked.
     * @param key
     *            The Key associated with the revoking Card.
     * @param token
     *            The identity token.
     */
    void revokeGlobal(VirgilCard card, VirgilKey key, IdentityValidationToken token);

    /**
     * Gets the {@link VirgilCard} by specified ID.
     * 
     * @param cardId
     *            The Card identifier.
     * @return The {@link VirgilCard}
     */
    VirgilCard get(String cardId);
}
