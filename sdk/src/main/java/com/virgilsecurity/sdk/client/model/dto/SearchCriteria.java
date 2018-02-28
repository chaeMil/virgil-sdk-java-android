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
package com.virgilsecurity.sdk.client.model.dto;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;

import com.virgilsecurity.sdk.client.model.CardScope;
import com.virgilsecurity.sdk.client.model.IdentityType;

/**
 * The criteria user for Virgil Cards searching.
 *
 * @author Andrii Iakovenko
 *
 */
public class SearchCriteria {

    private Collection<String> identities;

    private String identityType;

    private CardScope scope;

    public static SearchCriteria byIdentities(Collection<String> identities) {
        SearchCriteria criteria = new SearchCriteria();
        criteria.identities = identities;
        criteria.scope = CardScope.APPLICATION;

        return criteria;
    }

    public static SearchCriteria byIdentity(String identity) {
        SearchCriteria criteria = new SearchCriteria();
        criteria.identities = Arrays.asList(identity);
        criteria.scope = CardScope.APPLICATION;

        return criteria;
    }

    public static SearchCriteria byAppBundle(String bundle) {
        SearchCriteria criteria = new SearchCriteria();
        criteria.identities = Arrays.asList(bundle);
        criteria.identityType = IdentityType.APPLICATION.getValue();
        criteria.scope = CardScope.GLOBAL;

        return criteria;
    }

    /**
     * Create a new instance of {@code SearchCardsCriteria}
     *
     */
    public SearchCriteria() {
        this.identities = new HashSet<>();
    }

    /**
     * @return the identities
     */
    public Collection<String> getIdentities() {
        return Collections.unmodifiableCollection(identities);
    }

    /**
     * @param identities
     *            the identities to set
     */
    public void addIdentities(Collection<String> identities) {
        if (identities != null) {
            this.identities.addAll(identities);
        }
    }

    /**
     * @param identity
     *            the identities to set
     */
    public void addIdentity(String identity) {
        this.identities.add(identity);
    }

    /**
     * @return the identity type
     */
    public String getIdentityType() {
        return identityType;
    }

    /**
     * @param identityType
     *            the identityType to set
     */
    public void setIdentityType(String identityType) {
        this.identityType = identityType;
    }

    /**
     * @return the scope
     */
    public CardScope getScope() {
        return scope;
    }

    /**
     * @param scope
     *            the scope to set
     */
    public void setScope(CardScope scope) {
        this.scope = scope;
    }

}
