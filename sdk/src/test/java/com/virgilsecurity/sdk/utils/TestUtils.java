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

package com.virgilsecurity.sdk.utils;

import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.CardSignature;
import com.virgilsecurity.sdk.cards.SignerType;
import com.virgilsecurity.sdk.cards.model.RawCardContent;
import com.virgilsecurity.sdk.cards.model.RawSignature;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import org.junit.Assert;

import java.util.Objects;

public class TestUtils {

    public static boolean cardsEqualsSelfSignOnly(Card cardOne, Card cardTwo) {
        return cardOne.isOutdated() == cardTwo.isOutdated() &&
                Objects.equals(cardOne.getIdentifier(), cardTwo.getIdentifier()) &&
                Objects.equals(cardOne.getIdentity(), cardTwo.getIdentity()) &&
                Objects.equals(cardOne.getPublicKey(), cardTwo.getPublicKey()) &&
                Objects.equals(cardOne.getVersion(), cardTwo.getVersion()) &&
                Objects.equals(cardOne.getCreatedAt(), cardTwo.getCreatedAt()) &&
                Objects.equals(cardOne.getPreviousCardId(), cardTwo.getPreviousCardId()) &&
                Objects.equals(cardOne.getPreviousCard(), cardTwo.getPreviousCard()) &&
                Objects.equals(getSelfSignature(cardOne), getSelfSignature(cardTwo));
    }

    public static boolean cardModelsEqualsSelfSignOnly(RawSignedModel cardModelOne, RawSignedModel cardModelTwo) {
        RawCardContent rawCardContentOne =
                ConvertionUtils.deserializeFromJson(new String(cardModelOne.getContentSnapshot()),
                                                    RawCardContent.class);
        RawCardContent rawCardContentTwo =
                ConvertionUtils.deserializeFromJson(new String(cardModelTwo.getContentSnapshot()),
                                                    RawCardContent.class);

        return cardContentsEqualsSelfSignOnly(rawCardContentOne, rawCardContentTwo)
                && Objects.equals(getSelfSignature(cardModelOne), getSelfSignature(cardModelTwo));
    }

    public static boolean cardContentsEqualsSelfSignOnly(RawCardContent cardContentOne, RawCardContent cardContentTwo) {
        return Objects.equals(cardContentOne.getIdentity(), cardContentTwo.getIdentity()) &&
                Objects.equals(cardContentOne.getPublicKey(), cardContentTwo.getPublicKey()) &&
                Objects.equals(cardContentOne.getVersion(), cardContentTwo.getVersion()) &&
                cardContentOne.getCreatedAtTimestamp() == cardContentTwo.getCreatedAtTimestamp() &&
                Objects.equals(cardContentOne.getPreviousCardId(), cardContentTwo.getPreviousCardId());
    }

    private static CardSignature getSelfSignature(Card card) {
        for (CardSignature cardSignature : card.getSignatures()) {
            if (cardSignature.getSigner().equals(SignerType.SELF.getRawValue()))
                return cardSignature;
        }

        throw new NullPointerException("Card -> card must have at least 'self' signature");
    }

    private static RawSignature getSelfSignature(RawSignedModel cardModel) {
        for (RawSignature cardSignature : cardModel.getSignatures()) {
            if (cardSignature.getSigner().equals(SignerType.SELF.getRawValue()))
                return cardSignature;
        }

        throw new NullPointerException("Card -> card must have at least 'self' signature");
    }

    public static void assertCardsEquals(Card expectedCard, Card actualCard) {
        if (!cardsEqualsSelfSignOnly(expectedCard, actualCard))
            Assert.fail("\nExpected card:\n" + expectedCard.toString()
                                + "\n\nActual card:\n" + actualCard.toString());
    }

    public static void assertCardModelsEquals(RawSignedModel expectedCardModel, RawSignedModel actualCardModel) {
        if (!cardModelsEqualsSelfSignOnly(expectedCardModel, actualCardModel))
            Assert.fail("\nExpected card:\n" + expectedCardModel.toString()
                                + "\n\nActual card:\n" + actualCardModel.toString());
    }

    public static void assertCardContentsEquals(RawCardContent expectedCardContent, RawCardContent actualCardContent) {
        if (!cardContentsEqualsSelfSignOnly(expectedCardContent, actualCardContent))
            Assert.fail("\nExpected card:\n" + expectedCardContent.toString()
                                + "\n\nActual card:\n" + actualCardContent.toString());
    }
}
