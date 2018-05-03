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

package com.virgilsecurity.crypto;

public class VirgilPythia implements java.lang.AutoCloseable {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected VirgilPythia(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(VirgilPythia obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        virgil_crypto_javaJNI.delete_VirgilPythia(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  @Override
  public void close() {
    delete();
  }

  public VirgilPythiaBlindResult blind(byte[] password) {
    return new VirgilPythiaBlindResult(virgil_crypto_javaJNI.VirgilPythia_blind(swigCPtr, this, password), true);
  }

  public byte[] deblind(byte[] transformedPassword, byte[] blindingSecret) {
    return virgil_crypto_javaJNI.VirgilPythia_deblind(swigCPtr, this, transformedPassword, blindingSecret);
  }

  public VirgilPythiaTransformationKeyPair computeTransformationKeyPair(byte[] transformationKeyID, byte[] pythiaSecret, byte[] pythiaScopeSecret) {
    return new VirgilPythiaTransformationKeyPair(virgil_crypto_javaJNI.VirgilPythia_computeTransformationKeyPair(swigCPtr, this, transformationKeyID, pythiaSecret, pythiaScopeSecret), true);
  }

  public VirgilPythiaTransformResult transform(byte[] blindedPassword, byte[] tweak, byte[] transformationPrivateKey) {
    return new VirgilPythiaTransformResult(virgil_crypto_javaJNI.VirgilPythia_transform(swigCPtr, this, blindedPassword, tweak, transformationPrivateKey), true);
  }

  public VirgilPythiaProveResult prove(byte[] transformedPassword, byte[] blindedPassword, byte[] transformedTweak, VirgilPythiaTransformationKeyPair transformationKeyPair) {
    return new VirgilPythiaProveResult(virgil_crypto_javaJNI.VirgilPythia_prove(swigCPtr, this, transformedPassword, blindedPassword, transformedTweak, VirgilPythiaTransformationKeyPair.getCPtr(transformationKeyPair), transformationKeyPair), true);
  }

  public boolean verify(byte[] transformedPassword, byte[] blindedPassword, byte[] tweak, byte[] transformationPublicKey, byte[] proofValueC, byte[] proofValueU) {
    return virgil_crypto_javaJNI.VirgilPythia_verify(swigCPtr, this, transformedPassword, blindedPassword, tweak, transformationPublicKey, proofValueC, proofValueU);
  }

  public byte[] getPasswordUpdateToken(byte[] previousTransformationPrivateKey, byte[] newTransformationPrivateKey) {
    return virgil_crypto_javaJNI.VirgilPythia_getPasswordUpdateToken(swigCPtr, this, previousTransformationPrivateKey, newTransformationPrivateKey);
  }

  public byte[] updateDeblindedWithToken(byte[] deblindedPassword, byte[] passwordUpdateToken) {
    return virgil_crypto_javaJNI.VirgilPythia_updateDeblindedWithToken(swigCPtr, this, deblindedPassword, passwordUpdateToken);
  }

  public VirgilPythia() {
    this(virgil_crypto_javaJNI.new_VirgilPythia__SWIG_0(), true);
  }

  public VirgilPythia(VirgilPythia other) {
    this(virgil_crypto_javaJNI.new_VirgilPythia__SWIG_1(VirgilPythia.getCPtr(other), other), true);
  }

}
