/*
 * Copyright (c) 2015-2019, Virgil Security, Inc.
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

package com.virgilsecurity.sdk.cards.validation;

import com.virgilsecurity.sdk.cards.model.RawSignature;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.crypto.CardCrypto;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.Base64;
import com.virgilsecurity.sdk.utils.Validator;
import java.util.List;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * The {@link VirgilDeletedCardVerifier} is used to verify cards.
 */
public class VirgilDeletedCardVerifier implements DeletedCardVerifier {
  private static final Logger LOGGER = Logger.getLogger(VirgilDeletedCardVerifier.class.getName());

  private CardCrypto cardCrypto;
  private List<Whitelist> whitelists;
  private boolean skipVerify;

  /**
   * Instantiates a new Virgil card verifier. // TODO update comments
   */
  public VirgilDeletedCardVerifier() {
    this.skipVerify = true;
  }

  /**
   * Instantiates a new Virgil card verifier. // TODO update comments
   *
   * @param cardCrypto the card crypto.
   * @param whitelists the white lists that should contain Card signatures, otherwise Card
   *                   validation will be failed.
   */
  public VirgilDeletedCardVerifier(CardCrypto cardCrypto, List<Whitelist> whitelists) {
    Validator.checkNullAgrument(cardCrypto,
                                "VirgilCardVerifier -> 'cardCrypto' should not be null");
    Validator.checkNullAgrument(whitelists,
                                "VirgilCardVerifier -> 'whitelists' should not be null");

    this.cardCrypto = cardCrypto;
    this.whitelists = whitelists;
  }

  /**
   * Instantiates a new Virgil card verifier. // TODO update comments
   *
   * @param cardCrypto the card crypto.
   * @param whitelists the white lists that should contain Card signatures, otherwise Card
   *                   validation will be failed.
   */
  public VirgilDeletedCardVerifier(CardCrypto cardCrypto,
                                   List<Whitelist> whitelists,
                                   boolean skipVerify) {
    Validator.checkNullAgrument(cardCrypto,
                                "VirgilCardVerifier -> 'cardCrypto' should not be null");
    Validator.checkNullAgrument(whitelists,
                                "VirgilCardVerifier -> 'whitelists' should not be null");

    this.cardCrypto = cardCrypto;
    this.whitelists = whitelists;
    this.skipVerify = skipVerify;
  }

  /**
   * Sets white lists.
   *
   * @param whitelist the white lists
   */
  public void addWhiteList(Whitelist whitelist) {
    this.whitelists.add(whitelist);
  }

  /**
   * Gets card crypto.
   *
   * @return the card crypto
   */
  public CardCrypto getCardCrypto() {
    return cardCrypto;
  }

  /**
   * Gets white list.
   *
   * @return the white list
   */
  public List<Whitelist> getWhitelists() {
    return whitelists;
  }

  /**
   * Sets white lists.
   *
   * @param whitelists the white lists
   */
  public void setWhitelists(List<Whitelist> whitelists) {
    this.whitelists = whitelists;
  }

  @Override public boolean verifySignatures(RawSignedModel cardModel) throws CryptoException {
    if (skipVerify) {
      return true;
    }

    if (!whitelists.isEmpty()) {
      LOGGER.warning("Whitelist's should not be empty");
      return false;
    }

    int foundSignatures = 0;
    for (RawSignature signature : cardModel.getSignatures()) {
      for (Whitelist whitelist : whitelists) {
        for (VerifierCredentials verifierCredentials : whitelist.getVerifiersCredentials()) {
          if (verifierCredentials.getSigner().equals(signature.getSigner())) {
            foundSignatures++;
          }
        }
      }
    }

    if (cardModel.getSignatures().size() != foundSignatures) {
      LOGGER.info("You should provide Whitelist's for all signatures in"
                      + "deleted Card. Found corresponding signatures in "
                      + "whitelist: " + foundSignatures + "."
                      + " Should be: " + cardModel.getSignatures().size());
      return false;
    }

    for (Whitelist whitelist : whitelists) {
      for (VerifierCredentials verifierCredentials : whitelist.getVerifiersCredentials()) {
        for (RawSignature signature : cardModel.getSignatures()) {
          if (Objects.equals(signature.getSigner(), verifierCredentials.getSigner())) {
            PublicKey publicKey = cardCrypto.importPublicKey(verifierCredentials.getPublicKey());
            byte[] signatureBytes = Base64.decode(signature.getSignature());
            if (!cardCrypto.verifySignature(signatureBytes,
                                            cardModel.getContentSnapshot(),
                                            publicKey)) {
              LOGGER.info(String.format("Signer's '%s' signature validation failed",
                                        signature.getSigner()));
              return false;
            }
          }
        }
      }
    }

    return true;
  }
}
