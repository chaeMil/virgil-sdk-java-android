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

public class VirgilCipherBase implements java.lang.AutoCloseable {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected VirgilCipherBase(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(VirgilCipherBase obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        virgil_crypto_javaJNI.delete_VirgilCipherBase(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  @Override
  public void close() {
    delete();
  }

  public VirgilCipherBase() {
    this(virgil_crypto_javaJNI.new_VirgilCipherBase(), true);
  }

  public void addKeyRecipient(byte[] recipientId, byte[] publicKey) {
    virgil_crypto_javaJNI.VirgilCipherBase_addKeyRecipient(swigCPtr, this, recipientId, publicKey);
  }

  public void removeKeyRecipient(byte[] recipientId) {
    virgil_crypto_javaJNI.VirgilCipherBase_removeKeyRecipient(swigCPtr, this, recipientId);
  }

  public boolean keyRecipientExists(byte[] recipientId) {
    return virgil_crypto_javaJNI.VirgilCipherBase_keyRecipientExists(swigCPtr, this, recipientId);
  }

  public void addPasswordRecipient(byte[] pwd) {
    virgil_crypto_javaJNI.VirgilCipherBase_addPasswordRecipient(swigCPtr, this, pwd);
  }

  public void removePasswordRecipient(byte[] pwd) {
    virgil_crypto_javaJNI.VirgilCipherBase_removePasswordRecipient(swigCPtr, this, pwd);
  }

  public boolean passwordRecipientExists(byte[] password) {
    return virgil_crypto_javaJNI.VirgilCipherBase_passwordRecipientExists(swigCPtr, this, password);
  }

  public void removeAllRecipients() {
    virgil_crypto_javaJNI.VirgilCipherBase_removeAllRecipients(swigCPtr, this);
  }

  public byte[] getContentInfo() {
    return virgil_crypto_javaJNI.VirgilCipherBase_getContentInfo(swigCPtr, this);
  }

  public void setContentInfo(byte[] contentInfo) {
    virgil_crypto_javaJNI.VirgilCipherBase_setContentInfo(swigCPtr, this, contentInfo);
  }

  public static long defineContentInfoSize(byte[] data) {
    return virgil_crypto_javaJNI.VirgilCipherBase_defineContentInfoSize(data);
  }

  public VirgilCustomParams customParams() {
    return new VirgilCustomParams(virgil_crypto_javaJNI.VirgilCipherBase_customParams__SWIG_0(swigCPtr, this), false);
  }

  public static byte[] computeShared(byte[] publicKey, byte[] privateKey, byte[] privateKeyPassword) {
    return virgil_crypto_javaJNI.VirgilCipherBase_computeShared__SWIG_0(publicKey, privateKey, privateKeyPassword);
  }

  public static byte[] computeShared(byte[] publicKey, byte[] privateKey) {
    return virgil_crypto_javaJNI.VirgilCipherBase_computeShared__SWIG_1(publicKey, privateKey);
  }

}
