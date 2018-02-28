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
package com.virgilsecurity.crypto;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.nio.charset.StandardCharsets;

import org.junit.Before;
import org.junit.Test;
import org.junit.internal.ExactComparisonCriteria;

import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.KeysType;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilPFSTest {

    private static final String TEXT = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";
    private static final byte[] DATA = TEXT.getBytes(StandardCharsets.UTF_8);

    // Initiator
    private static final String ALICE = "alice";

    // Receiver
    private static final String BOB = "bob";

    private Crypto crypto;
    private byte[] aliceId, bobId;
    private VirgilPFSPrivateKey alicePFSPrivateKey, aliceEphPrivateKey, bobIdentityPrivateKey, bobLTPrivateKey;
    private VirgilPFSPublicKey aliceIdentityPublicKey, aliceEphPublicKey, bobIdentityPublicKey, bobLTPublicKey;
    private VirgilPFS alicePFS, bobPFS;

    @Before
    public void setUp() {
        crypto = new VirgilCrypto(KeysType.EC_CURVE25519);

        /** Generate identity keys */
        // Alice keys
        KeyPair keyPair = crypto.generateKeys();
        aliceId = keyPair.getPublicKey().getId();
        alicePFSPrivateKey = new VirgilPFSPrivateKey(keyPair.getPrivateKey().getValue());
        aliceIdentityPublicKey = new VirgilPFSPublicKey(keyPair.getPublicKey().getValue());

        // Bob keys
        keyPair = crypto.generateKeys();
        bobId = keyPair.getPublicKey().getId();
        bobIdentityPrivateKey = new VirgilPFSPrivateKey(keyPair.getPrivateKey().getValue());
        bobIdentityPublicKey = new VirgilPFSPublicKey(keyPair.getPublicKey().getValue());

        /** Generate ephemeral keys */
        // Alice key
        keyPair = crypto.generateKeys();
        aliceEphPrivateKey = new VirgilPFSPrivateKey(keyPair.getPrivateKey().getValue());
        aliceEphPublicKey = new VirgilPFSPublicKey(keyPair.getPublicKey().getValue());

        // Bob key
        keyPair = crypto.generateKeys();
        bobLTPrivateKey = new VirgilPFSPrivateKey(keyPair.getPrivateKey().getValue());
        bobLTPublicKey = new VirgilPFSPublicKey(keyPair.getPublicKey().getValue());
    }

    @Test
    public void encrypt_decrypt_LT() {
        /** Encrypt */
        // Prepare PFS info
        VirgilPFSInitiatorPrivateInfo alicePrivateInfo = new VirgilPFSInitiatorPrivateInfo(alicePFSPrivateKey,
                aliceEphPrivateKey);
        VirgilPFSResponderPublicInfo bobPublicInfo = new VirgilPFSResponderPublicInfo(bobIdentityPublicKey,
                bobLTPublicKey);

        // Initialize PFS
        alicePFS = new VirgilPFS();
        alicePFS.startInitiatorSession(alicePrivateInfo, bobPublicInfo);
        VirgilPFSEncryptedMessage encryptedMessage = alicePFS.encrypt(DATA);

        assertNotNull(encryptedMessage);

        /** Decrypt */
        VirgilPFSInitiatorPublicInfo alicePublicInfo = new VirgilPFSInitiatorPublicInfo(aliceIdentityPublicKey,
                aliceEphPublicKey);
        VirgilPFSResponderPrivateInfo bobPrivateInfo = new VirgilPFSResponderPrivateInfo(bobIdentityPrivateKey,
                bobLTPrivateKey);

        bobPFS = new VirgilPFS();
        bobPFS.startResponderSession(bobPrivateInfo, alicePublicInfo);
        byte[] decrypted = bobPFS.decrypt(encryptedMessage);

        assertNotNull(decrypted);
        assertArrayEquals(DATA, decrypted);
    }

    @Test
    public void encrypt_decrypt_OT() {
        /** Generate one time keys */
        KeyPair keyPair = crypto.generateKeys();
        VirgilPFSPrivateKey bobOTPrivateKey = new VirgilPFSPrivateKey(keyPair.getPrivateKey().getValue());
        VirgilPFSPublicKey bobOTPublicKey = new VirgilPFSPublicKey(keyPair.getPublicKey().getValue());

        /** Encrypt */
        // Prepare PFS info
        VirgilPFSInitiatorPrivateInfo alicePrivateInfo = new VirgilPFSInitiatorPrivateInfo(alicePFSPrivateKey,
                aliceEphPrivateKey);
        VirgilPFSResponderPublicInfo bobPublicInfo = new VirgilPFSResponderPublicInfo(bobIdentityPublicKey,
                bobLTPublicKey, bobOTPublicKey);

        // Initialize PFS
        alicePFS = new VirgilPFS();
        alicePFS.startInitiatorSession(alicePrivateInfo, bobPublicInfo);
        VirgilPFSEncryptedMessage encryptedMessage = alicePFS.encrypt(DATA);

        assertNotNull(encryptedMessage);
        assertNotNull(encryptedMessage.getCipherText());
        assertThat(DATA, not(equalTo(encryptedMessage.getCipherText())));

        /** Decrypt */
        VirgilPFSInitiatorPublicInfo alicePublicInfo = new VirgilPFSInitiatorPublicInfo(aliceIdentityPublicKey,
                aliceEphPublicKey);
        VirgilPFSResponderPrivateInfo bobPrivateInfo = new VirgilPFSResponderPrivateInfo(bobIdentityPrivateKey,
                bobLTPrivateKey, bobOTPrivateKey);

        bobPFS = new VirgilPFS();
        bobPFS.startResponderSession(bobPrivateInfo, alicePublicInfo);
        byte[] decrypted = bobPFS.decrypt(encryptedMessage);

        assertNotNull(decrypted);
        assertArrayEquals(DATA, decrypted);
    }

    @Test
    public void encrypt_decrypt_OT_multiple_times() {
        for (int i = 0; i < 10; i++) {
            encrypt_decrypt_OT();
        }
    }

}
