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

public class VirgilCMSEncryptedContent extends VirgilAsn1Compatible implements java.lang.AutoCloseable {
  protected static long getCPtr(VirgilCMSEncryptedContent obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  private transient long swigCPtr;

  public VirgilCMSEncryptedContent() {
    this(virgil_crypto_javaJNI.new_VirgilCMSEncryptedContent__SWIG_0(), true);
  }

  protected VirgilCMSEncryptedContent(long cPtr, boolean cMemoryOwn) {
    super(virgil_crypto_javaJNI.VirgilCMSEncryptedContent_SWIGUpcast(cPtr), cMemoryOwn);
    swigCPtr = cPtr;
  }

  public VirgilCMSEncryptedContent(VirgilCMSEncryptedContent other) {
    this(virgil_crypto_javaJNI.new_VirgilCMSEncryptedContent__SWIG_1(VirgilCMSEncryptedContent.getCPtr(other), other), true);
  }

  @Override
  public void close() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        virgil_crypto_javaJNI.delete_VirgilCMSEncryptedContent(swigCPtr);
      }
      swigCPtr = 0;
    }
    super.delete();
  }

  protected void finalize() {
    delete();
  }

  public byte[] getContentEncryptionAlgorithm() {
    return virgil_crypto_javaJNI.VirgilCMSEncryptedContent_contentEncryptionAlgorithm_get(swigCPtr, this);
  }

  public byte[] getEncryptedContent() {
    return virgil_crypto_javaJNI.VirgilCMSEncryptedContent_encryptedContent_get(swigCPtr, this);
  }

  public void setContentEncryptionAlgorithm(byte[] value) {
    virgil_crypto_javaJNI.VirgilCMSEncryptedContent_contentEncryptionAlgorithm_set(swigCPtr, this, value);
  }

  public void setEncryptedContent(byte[] value) {
    virgil_crypto_javaJNI.VirgilCMSEncryptedContent_encryptedContent_set(swigCPtr, this, value);
  }

}
