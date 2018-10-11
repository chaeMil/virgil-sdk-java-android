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

import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.exception.NullArgumentException;

/**
 * The Virgil implementation of access token signer.
 *
 * @see AccessTokenSigner
 * @see PrivateKey
 * @see PublicKey
 */
public class VirgilAccessTokenSigner implements AccessTokenSigner {

  private static final String ALGORITHM = "VEDS512";

  private VirgilCrypto virgilCrypto;

  /**
   * Instantiates a new Virgil access token signer.
   */
  public VirgilAccessTokenSigner() {
    this.virgilCrypto = new VirgilCrypto();
  }

  /**
   * Instantiates a new Virgil access token signer.
   * 
   * @param virgilCrypto
   *          the Virgil Crypto.
   */
  public VirgilAccessTokenSigner(VirgilCrypto virgilCrypto) {
    this.virgilCrypto = virgilCrypto;
  }

  @Override
  public byte[] generateTokenSignature(byte[] token, PrivateKey privateKey) throws CryptoException {
    if (privateKey == null) {
      throw new NullArgumentException("privateKey");
    }
    if (!(privateKey instanceof VirgilPrivateKey)) {
      throw new CryptoException(
          "VirgilAccessTokenSigner -> 'privateKey' should be of 'VirgilPrivateKey' type");
    }

    return virgilCrypto.generateSignature(token, (VirgilPrivateKey) privateKey);
  }

  @Override
  public String getAlgorithm() {
    return ALGORITHM;
  }

  /**
   * Gets Virgil crypto.
   *
   * @return the Virgil crypto
   */
  public VirgilCrypto getVirgilCrypto() {
    return virgilCrypto;
  }

  @Override
  public boolean verifyTokenSignature(byte[] signature, byte[] data, PublicKey publicKey)
      throws CryptoException {
    if (!(publicKey instanceof VirgilPublicKey)) {
      throw new CryptoException(
          "VirgilAccessTokenSigner -> 'publicKey' should be of 'VirgilPublicKey' type");
    }

    return virgilCrypto.verifySignature(signature, data, (VirgilPublicKey) publicKey);
  }
}
