/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 3.0.8
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package com.virgilsecurity.crypto;

public class VirgilAsymmetricCipher extends VirgilAsn1Compatible implements java.lang.AutoCloseable {
  private transient long swigCPtr;

  protected VirgilAsymmetricCipher(long cPtr, boolean cMemoryOwn) {
    super(virgil_crypto_javaJNI.VirgilAsymmetricCipher_SWIGUpcast(cPtr), cMemoryOwn);
    swigCPtr = cPtr;
  }

  protected static long getCPtr(VirgilAsymmetricCipher obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        virgil_crypto_javaJNI.delete_VirgilAsymmetricCipher(swigCPtr);
      }
      swigCPtr = 0;
    }
    super.delete();
  }

  @Override
  public void close() {
    delete();
  }

  public VirgilAsymmetricCipher() {
    this(virgil_crypto_javaJNI.new_VirgilAsymmetricCipher(), true);
  }

  public long keySize() {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_keySize(swigCPtr, this);
  }

  public long keyLength() {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_keyLength(swigCPtr, this);
  }

  public static boolean isKeyPairMatch(byte[] publicKey, byte[] privateKey, byte[] privateKeyPassword) {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_isKeyPairMatch__SWIG_0(publicKey, privateKey, privateKeyPassword);
  }

  public static boolean isKeyPairMatch(byte[] publicKey, byte[] privateKey) {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_isKeyPairMatch__SWIG_1(publicKey, privateKey);
  }

  public static boolean isPublicKeyValid(byte[] key) {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_isPublicKeyValid(key);
  }

  public static void checkPublicKey(byte[] key) {
    virgil_crypto_javaJNI.VirgilAsymmetricCipher_checkPublicKey(key);
  }

  public static boolean checkPrivateKeyPassword(byte[] key, byte[] pwd) {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_checkPrivateKeyPassword(key, pwd);
  }

  public static boolean isPrivateKeyEncrypted(byte[] privateKey) {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_isPrivateKeyEncrypted(privateKey);
  }

  public void setPrivateKey(byte[] key, byte[] pwd) {
    virgil_crypto_javaJNI.VirgilAsymmetricCipher_setPrivateKey__SWIG_0(swigCPtr, this, key, pwd);
  }

  public void setPrivateKey(byte[] key) {
    virgil_crypto_javaJNI.VirgilAsymmetricCipher_setPrivateKey__SWIG_1(swigCPtr, this, key);
  }

  public void setPublicKey(byte[] key) {
    virgil_crypto_javaJNI.VirgilAsymmetricCipher_setPublicKey(swigCPtr, this, key);
  }

  public void genKeyPair(VirgilKeyPair.Type type) {
    virgil_crypto_javaJNI.VirgilAsymmetricCipher_genKeyPair(swigCPtr, this, type.swigValue());
  }

  public void genKeyPairFrom(VirgilAsymmetricCipher other) {
    virgil_crypto_javaJNI.VirgilAsymmetricCipher_genKeyPairFrom(swigCPtr, this, VirgilAsymmetricCipher.getCPtr(other), other);
  }

  public static byte[] computeShared(VirgilAsymmetricCipher publicContext, VirgilAsymmetricCipher privateContext) {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_computeShared(VirgilAsymmetricCipher.getCPtr(publicContext), publicContext, VirgilAsymmetricCipher.getCPtr(privateContext), privateContext);
  }

  public byte[] exportPrivateKeyToDER(byte[] pwd) {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_exportPrivateKeyToDER__SWIG_0(swigCPtr, this, pwd);
  }

  public byte[] exportPrivateKeyToDER() {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_exportPrivateKeyToDER__SWIG_1(swigCPtr, this);
  }

  public byte[] exportPublicKeyToDER() {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_exportPublicKeyToDER(swigCPtr, this);
  }

  public byte[] exportPrivateKeyToPEM(byte[] pwd) {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_exportPrivateKeyToPEM__SWIG_0(swigCPtr, this, pwd);
  }

  public byte[] exportPrivateKeyToPEM() {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_exportPrivateKeyToPEM__SWIG_1(swigCPtr, this);
  }

  public byte[] exportPublicKeyToPEM() {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_exportPublicKeyToPEM(swigCPtr, this);
  }

  public VirgilKeyPair.Type getKeyType() {
    return VirgilKeyPair.Type.swigToEnum(virgil_crypto_javaJNI.VirgilAsymmetricCipher_getKeyType(swigCPtr, this));
  }

  public void setKeyType(VirgilKeyPair.Type keyType) {
    virgil_crypto_javaJNI.VirgilAsymmetricCipher_setKeyType(swigCPtr, this, keyType.swigValue());
  }

  public byte[] getPublicKeyBits() {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_getPublicKeyBits(swigCPtr, this);
  }

  public void setPublicKeyBits(byte[] bits) {
    virgil_crypto_javaJNI.VirgilAsymmetricCipher_setPublicKeyBits(swigCPtr, this, bits);
  }

  public byte[] encrypt(byte[] in) {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_encrypt(swigCPtr, this, in);
  }

  public byte[] decrypt(byte[] in) {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_decrypt(swigCPtr, this, in);
  }

  public byte[] sign(byte[] digest, int hashType) {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_sign(swigCPtr, this, digest, hashType);
  }

  public boolean verify(byte[] digest, byte[] sign, int hashType) {
    return virgil_crypto_javaJNI.VirgilAsymmetricCipher_verify(swigCPtr, this, digest, sign, hashType);
  }

}
