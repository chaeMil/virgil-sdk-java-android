/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 3.0.8
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package com.virgilsecurity.crypto;

public class VirgilStreamCipher extends VirgilCipherBase implements java.lang.AutoCloseable {
  private transient long swigCPtr;

  protected VirgilStreamCipher(long cPtr, boolean cMemoryOwn) {
    super(virgil_crypto_javaJNI.VirgilStreamCipher_SWIGUpcast(cPtr), cMemoryOwn);
    swigCPtr = cPtr;
  }

  protected static long getCPtr(VirgilStreamCipher obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        virgil_crypto_javaJNI.delete_VirgilStreamCipher(swigCPtr);
      }
      swigCPtr = 0;
    }
    super.delete();
  }

  @Override
  public void close() {
    delete();
  }

  public void encrypt(VirgilDataSource source, VirgilDataSink sink, boolean embedContentInfo) {
    virgil_crypto_javaJNI.VirgilStreamCipher_encrypt__SWIG_0(swigCPtr, this, VirgilDataSource.getCPtr(source), source, VirgilDataSink.getCPtr(sink), sink, embedContentInfo);
  }

  public void encrypt(VirgilDataSource source, VirgilDataSink sink) {
    virgil_crypto_javaJNI.VirgilStreamCipher_encrypt__SWIG_1(swigCPtr, this, VirgilDataSource.getCPtr(source), source, VirgilDataSink.getCPtr(sink), sink);
  }

  public void decryptWithKey(VirgilDataSource source, VirgilDataSink sink, byte[] recipientId, byte[] privateKey, byte[] privateKeyPassword) {
    virgil_crypto_javaJNI.VirgilStreamCipher_decryptWithKey__SWIG_0(swigCPtr, this, VirgilDataSource.getCPtr(source), source, VirgilDataSink.getCPtr(sink), sink, recipientId, privateKey, privateKeyPassword);
  }

  public void decryptWithKey(VirgilDataSource source, VirgilDataSink sink, byte[] recipientId, byte[] privateKey) {
    virgil_crypto_javaJNI.VirgilStreamCipher_decryptWithKey__SWIG_1(swigCPtr, this, VirgilDataSource.getCPtr(source), source, VirgilDataSink.getCPtr(sink), sink, recipientId, privateKey);
  }

  public void decryptWithPassword(VirgilDataSource source, VirgilDataSink sink, byte[] pwd) {
    virgil_crypto_javaJNI.VirgilStreamCipher_decryptWithPassword(swigCPtr, this, VirgilDataSource.getCPtr(source), source, VirgilDataSink.getCPtr(sink), sink, pwd);
  }

  public VirgilStreamCipher() {
    this(virgil_crypto_javaJNI.new_VirgilStreamCipher(), true);
  }

}
