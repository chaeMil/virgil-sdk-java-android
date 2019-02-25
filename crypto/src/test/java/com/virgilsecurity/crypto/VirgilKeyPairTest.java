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

package com.virgilsecurity.crypto;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Unit tests for {@link VirgilKeyPair}.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilKeyPairTest {

  private static final byte[] PWD = "12345678".getBytes();
  private static final byte[] PRIVATE_KEY_PEM = ("-----BEGIN PRIVATE KEY-----\n"
      + "MC4CAQAwBQYDK2VwBCIEINzRBu+EahDeUI8R9GQNGBRl1wKNJzPlZbXWpyiZL7/o\n"
      + "-----END PRIVATE KEY-----").getBytes();

  @Test
  public void privateKeyToDer() {
    byte[] key = VirgilKeyPair.privateKeyToDER(PRIVATE_KEY_PEM);
    assertNotNull(key);
    assertTrue(key.length > 0);
  }

  @Test
  public void privateKeyToPem() {
    VirgilKeyPair keyPair = VirgilKeyPair.generateRecommended();

    byte[] key = VirgilKeyPair.privateKeyToPEM(keyPair.privateKey());
    assertNotNull(key);
  }

  @Test
  public void privateKeyToPem_withPassword() {
    VirgilKeyPair keyPair = VirgilKeyPair.generateRecommended(PWD);

    byte[] key = VirgilKeyPair.privateKeyToPEM(keyPair.privateKey(), PWD);
    assertNotNull(key);
    assertTrue(key.length > 0);
  }

}
