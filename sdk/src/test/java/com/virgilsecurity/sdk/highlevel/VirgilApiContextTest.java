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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;

import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.client.VirgilClient;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.device.DeviceManager;
import com.virgilsecurity.sdk.device.DefaultDeviceManager;
import com.virgilsecurity.sdk.storage.KeyStorage;
import com.virgilsecurity.sdk.storage.VirgilKeyStorage;

/**
 * Unit tests for {@code VirgilConfig}
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilApiContextTest {

    private VirgilApiContext virgilApiContext;

    @Before
    public void setUp() {
        virgilApiContext = new VirgilApiContext();
    }

    @Test
    public void instantiate_defaultConstructor() {
        virgilApiContext = new VirgilApiContext();

        assertNull(virgilApiContext.getAccessToken());
        assertNull(virgilApiContext.getCredentials());

        assertThat(virgilApiContext.getCrypto(), instanceOf(VirgilCrypto.class));
        assertThat(virgilApiContext.getKeyStorage(), instanceOf(VirgilKeyStorage.class));
        assertThat(virgilApiContext.getDeviceManager(), instanceOf(DefaultDeviceManager.class));
        assertThat(virgilApiContext.getClient(), instanceOf(VirgilClient.class));
    }

    @Test
    public void instantiate_nullAccessToken() {
        virgilApiContext = new VirgilApiContext(null);
        assertNull(virgilApiContext.getAccessToken());
    }

    @Test
    public void instantiate_emptyAccessToken() {
        virgilApiContext = new VirgilApiContext("");
        assertEquals("", virgilApiContext.getAccessToken());
    }

    @Test
    public void instantiate_blankAccessToken() {
        virgilApiContext = new VirgilApiContext(" \t\n");
        assertEquals(" \t\n", virgilApiContext.getAccessToken());
    }

    @Test
    public void instantiate_accessToken() {
        virgilApiContext = new VirgilApiContext("The access token");
        assertEquals("The access token", virgilApiContext.getAccessToken());
    }

    @Test
    public void setCrypto() {
        Crypto crypto = new VirgilCrypto();
        virgilApiContext.setCrypto(crypto);

        assertSame(crypto, virgilApiContext.getCrypto());
    }

    @Test
    public void setKeyStorage() {
        KeyStorage storage = new VirgilKeyStorage();
        virgilApiContext.setKeyStorage(storage);

        assertSame(storage, virgilApiContext.getKeyStorage());
    }

    @Test
    public void setDeviceManager() {
        DeviceManager deviceManager = new DefaultDeviceManager();
        virgilApiContext.setDeviceManager(deviceManager);

        assertSame(deviceManager, virgilApiContext.getDeviceManager());
    }
}
