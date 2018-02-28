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
package com.virgilsecurity.sdk.client.exceptions;

import java.util.ArrayList;
import java.util.List;

import com.virgilsecurity.sdk.client.model.CardModel;

/**
 * This exception occurred when card validation failed.
 *
 * @author Andrii Iakovenko
 *
 */
public class CardValidationException extends VirgilClientException {

    private static final long serialVersionUID = 8029782256278798813L;

    private List<CardModel> invalidCards;

    /**
     * Create a new instance of {@code CardValidationException}
     *
     * @param invalidCards
     *            the list of invalid cards.
     */
    public CardValidationException(List<CardModel> invalidCards) {
        super("One or more cards didn't pass the validation");
        this.invalidCards = new ArrayList<>(invalidCards);
    }

    /**
     * Create a new instance of {@code CardValidationException}
     *
     * @param message
     *            the message.
     * @param invalidCards
     *            the list of invalid cards.
     */
    public CardValidationException(String message, List<CardModel> invalidCards) {
        super(message);
        this.invalidCards = new ArrayList<>(invalidCards);
    }

    /**
     * Create new instance of {@link CardValidationException}.
     * 
     * @param code
     *            the error code.
     * @param message
     *            the message.
     */
    public CardValidationException(int code, String message) {
        super(code, message);
    }

    /**
     * Gets the invalid cards.
     * 
     * @return the invalidCards
     */
    public List<CardModel> getInvalidCards() {
        return invalidCards;
    }

}
