/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 3.0.8
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package com.virgilsecurity.crypto;

public class VirgilAsn1Writer implements java.lang.AutoCloseable {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected VirgilAsn1Writer(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(VirgilAsn1Writer obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        virgil_crypto_javaJNI.delete_VirgilAsn1Writer(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  @Override
  public void close() {
    delete();
  }

  public VirgilAsn1Writer() {
    this(virgil_crypto_javaJNI.new_VirgilAsn1Writer__SWIG_0(), true);
  }

  public VirgilAsn1Writer(long capacity) {
    this(virgil_crypto_javaJNI.new_VirgilAsn1Writer__SWIG_1(capacity), true);
  }

  public void reset() {
    virgil_crypto_javaJNI.VirgilAsn1Writer_reset__SWIG_0(swigCPtr, this);
  }

  public void reset(long capacity) {
    virgil_crypto_javaJNI.VirgilAsn1Writer_reset__SWIG_1(swigCPtr, this, capacity);
  }

  public byte[] finish() {
    return virgil_crypto_javaJNI.VirgilAsn1Writer_finish(swigCPtr, this);
  }

  public long writeInteger(int value) {
    return virgil_crypto_javaJNI.VirgilAsn1Writer_writeInteger(swigCPtr, this, value);
  }

  public long writeBool(boolean value) {
    return virgil_crypto_javaJNI.VirgilAsn1Writer_writeBool(swigCPtr, this, value);
  }

  public long writeNull() {
    return virgil_crypto_javaJNI.VirgilAsn1Writer_writeNull(swigCPtr, this);
  }

  public long writeOctetString(byte[] data) {
    return virgil_crypto_javaJNI.VirgilAsn1Writer_writeOctetString(swigCPtr, this, data);
  }

  public long writeUTF8String(byte[] data) {
    return virgil_crypto_javaJNI.VirgilAsn1Writer_writeUTF8String(swigCPtr, this, data);
  }

  public long writeContextTag(short tag, long len) {
    return virgil_crypto_javaJNI.VirgilAsn1Writer_writeContextTag(swigCPtr, this, tag, len);
  }

  public long writeData(byte[] data) {
    return virgil_crypto_javaJNI.VirgilAsn1Writer_writeData(swigCPtr, this, data);
  }

  public long writeOID(String oid) {
    return virgil_crypto_javaJNI.VirgilAsn1Writer_writeOID(swigCPtr, this, oid);
  }

  public long writeSequence(long len) {
    return virgil_crypto_javaJNI.VirgilAsn1Writer_writeSequence(swigCPtr, this, len);
  }

  public long writeSet(SWIGTYPE_p_std__vectorT_virgil__crypto__VirgilByteArray_t set) {
    return virgil_crypto_javaJNI.VirgilAsn1Writer_writeSet(swigCPtr, this, SWIGTYPE_p_std__vectorT_virgil__crypto__VirgilByteArray_t.getCPtr(set));
  }

}
