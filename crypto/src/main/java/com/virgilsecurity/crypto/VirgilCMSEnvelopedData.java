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

public class VirgilCMSEnvelopedData extends VirgilAsn1Compatible implements java.lang.AutoCloseable {
  private transient long swigCPtr;

  protected VirgilCMSEnvelopedData(long cPtr, boolean cMemoryOwn) {
    super(virgil_crypto_javaJNI.VirgilCMSEnvelopedData_SWIGUpcast(cPtr), cMemoryOwn);
    swigCPtr = cPtr;
  }

  protected static long getCPtr(VirgilCMSEnvelopedData obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        virgil_crypto_javaJNI.delete_VirgilCMSEnvelopedData(swigCPtr);
      }
      swigCPtr = 0;
    }
    super.delete();
  }

  @Override
  public void close() {
    delete();
  }

  public void setKeyTransRecipients(SWIGTYPE_p_std__vectorT_virgil__crypto__foundation__cms__VirgilCMSKeyTransRecipient_t value) {
    virgil_crypto_javaJNI.VirgilCMSEnvelopedData_keyTransRecipients_set(swigCPtr, this, SWIGTYPE_p_std__vectorT_virgil__crypto__foundation__cms__VirgilCMSKeyTransRecipient_t.getCPtr(value));
  }

  public SWIGTYPE_p_std__vectorT_virgil__crypto__foundation__cms__VirgilCMSKeyTransRecipient_t getKeyTransRecipients() {
    long cPtr = virgil_crypto_javaJNI.VirgilCMSEnvelopedData_keyTransRecipients_get(swigCPtr, this);
    return (cPtr == 0) ? null : new SWIGTYPE_p_std__vectorT_virgil__crypto__foundation__cms__VirgilCMSKeyTransRecipient_t(cPtr, false);
  }

  public void setPasswordRecipients(SWIGTYPE_p_std__vectorT_virgil__crypto__foundation__cms__VirgilCMSPasswordRecipient_t value) {
    virgil_crypto_javaJNI.VirgilCMSEnvelopedData_passwordRecipients_set(swigCPtr, this, SWIGTYPE_p_std__vectorT_virgil__crypto__foundation__cms__VirgilCMSPasswordRecipient_t.getCPtr(value));
  }

  public SWIGTYPE_p_std__vectorT_virgil__crypto__foundation__cms__VirgilCMSPasswordRecipient_t getPasswordRecipients() {
    long cPtr = virgil_crypto_javaJNI.VirgilCMSEnvelopedData_passwordRecipients_get(swigCPtr, this);
    return (cPtr == 0) ? null : new SWIGTYPE_p_std__vectorT_virgil__crypto__foundation__cms__VirgilCMSPasswordRecipient_t(cPtr, false);
  }

  public void setEncryptedContent(VirgilCMSEncryptedContent value) {
    virgil_crypto_javaJNI.VirgilCMSEnvelopedData_encryptedContent_set(swigCPtr, this, VirgilCMSEncryptedContent.getCPtr(value), value);
  }

  public VirgilCMSEncryptedContent getEncryptedContent() {
    long cPtr = virgil_crypto_javaJNI.VirgilCMSEnvelopedData_encryptedContent_get(swigCPtr, this);
    return (cPtr == 0) ? null : new VirgilCMSEncryptedContent(cPtr, false);
  }

  public VirgilCMSEnvelopedData() {
    this(virgil_crypto_javaJNI.new_VirgilCMSEnvelopedData__SWIG_0(), true);
  }

  public VirgilCMSEnvelopedData(VirgilCMSEnvelopedData other) {
    this(virgil_crypto_javaJNI.new_VirgilCMSEnvelopedData__SWIG_1(VirgilCMSEnvelopedData.getCPtr(other), other), true);
  }

}
