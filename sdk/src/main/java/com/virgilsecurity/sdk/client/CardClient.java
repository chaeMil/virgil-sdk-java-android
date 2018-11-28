package com.virgilsecurity.sdk.client;

import java.util.Collection;
import java.util.List;

import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.utils.Tuple;

/**
 * Interface representing operations with Virgil Cards service.
 * 
 * @author Andrii Iakovenko
 *
 */
public interface CardClient {

  /**
   * Get card from Virgil Services by specified identifier.
   *
   * @param cardId the card identifier.
   * @param token  token to authorize the request.
   * @return the card loaded from Virgil Cards service.
   * @throws VirgilServiceException if service call failed
   */
  public Tuple<RawSignedModel, Boolean> getCard(String cardId, String token)
      throws VirgilServiceException;

  /**
   * Publishes card in Virgil Cards service.
   *
   * @param rawCard raw signed model of card to be published.
   * @param token   token to authorize the request.
   * @return the {@link RawSignedModel} of the Card that is published to Virgil Cards service.
   * @throws VirgilServiceException if an error occurred while publishing Card.
   */
  public RawSignedModel publishCard(RawSignedModel rawCard, String token)
      throws VirgilServiceException;

  /**
   * Search cards Virgil Services by specified identity.
   *
   * @param identity the identity for search.
   * @param token    token to authorize the request.
   * @return A list of found cards.
   * @throws VirgilServiceException if service call failed
   */
  public List<RawSignedModel> searchCards(String identity, String token)
      throws VirgilServiceException;

  /**
   * Search cards Virgil Services by specified identity.
   *
   * @param identities the identity for search.
   * @param token      token to authorize the request.
   * @return A list of found cards.
   * @throws VirgilServiceException if service call failed
   */
  public List<RawSignedModel> searchCards(Collection<String> identities, String token)
      throws VirgilServiceException;
}
