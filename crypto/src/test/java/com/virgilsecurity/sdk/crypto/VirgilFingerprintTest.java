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
package com.virgilsecurity.sdk.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

/**
 * Unit tests for {@link VirgilFingerprint}.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilFingerprintTest {

    private static final String FINGERPRINT = "3058300d060960864801650304020205000447304502210094faae1dda67f32a654cdecba0ba555000584d30099c5127cd839a95940ea80702200db99d08bbb31e6214e73c7ded430ce2415de3a4c6a55b3291b13285d92430ec";

    @Test
    public void create_fromByteArray() {
        Fingerprint fingerprint = new VirgilFingerprint(DatatypeConverter.parseHexBinary(FINGERPRINT));
        assertNotNull(fingerprint.getValue());
        assertEquals(FINGERPRINT, DatatypeConverter.printHexBinary(fingerprint.getValue()).toLowerCase());
    }

    @Test
    public void create_fromString() {
        Fingerprint fingerprint = new VirgilFingerprint(FINGERPRINT);
        assertNotNull(fingerprint.getValue());
        assertEquals(FINGERPRINT, DatatypeConverter.printHexBinary(fingerprint.getValue()).toLowerCase());
    }

    @Test
    public void toHex() {
        Fingerprint fingerprint = new VirgilFingerprint(FINGERPRINT);
        assertNotNull(fingerprint.getValue());
        assertEquals(FINGERPRINT, fingerprint.toHex());
    }

}
