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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class virgil_crypto_javaJNI {

    private static final String MACOS_OS_NAME = "mac os";
    private static final String LINUX_OS_NAME = "linux";
    private static final String WINDOWS_OS_NAME = "windows";
    private static final String UNKNOWN_OS = "unknown";

    private static final String MACOS_LIBS_DIRECTORY = MACOS_OS_NAME;
    private static final String LINUX_LIBS_DIRECTORY = LINUX_OS_NAME;
    private static final String WINDOWS_LIBS_DIRECTORY = WINDOWS_OS_NAME;

    private static final String SEPARATOR = "/";

    static {
        try {
            loadNativeLibrary("virgil_crypto_java");
        } catch (Exception error) {
            System.err.println("Native code library failed to load. \n" + error);
        }
        swig_module_init();
    }

    private static final String getLibraryFileSuffix(String os) {
        switch (os) {
        case LINUX_OS_NAME:
        case MACOS_OS_NAME:
            return ".so";
        case WINDOWS_OS_NAME:
            return ".dll";
        }
        return "";
    }

    /**
     * Get operation system by operation system name
     * 
     * @param osName
     *            The OS name.
     * @return
     */
    private static final String getOS(String osName) {
        for (String os : new String[] { LINUX_OS_NAME, WINDOWS_OS_NAME, MACOS_OS_NAME }) {
            if (osName.startsWith(os)) {
                return os;
            }
        }
        return UNKNOWN_OS;
    }

    private static final String getResourceDirectory(String os, String osArch) {
        switch (os) {
        case LINUX_OS_NAME:
            return LINUX_LIBS_DIRECTORY;
        case MACOS_OS_NAME:
            return MACOS_LIBS_DIRECTORY;
        case WINDOWS_OS_NAME:
            return WINDOWS_LIBS_DIRECTORY + SEPARATOR + osArch;
        }
        return "";
    }

    public static void loadNativeLibrary(String libraryName) throws IOException {

        try {
            System.loadLibrary(libraryName);
            // Library is loaded (Android or exists in java.library.path). We
            // can exit
            return;
        } catch (Throwable e) {
            // Library couldn't be loaded yet. We'll load it later.
        }

        // Build native library name according to current system
        String osName = System.getProperty("os.name").toLowerCase();
        String os = getOS(osName);
        String osArch = System.getProperty("os.arch").toLowerCase();

        StringBuilder resourceName = new StringBuilder();
        resourceName.append(getResourceDirectory(os, osArch)).append(SEPARATOR).append(libraryName);

        // Save native library as temporary file
        InputStream in = virgil_crypto_javaJNI.class.getClassLoader().getResourceAsStream(resourceName.toString());
        if (in == null) {
            throw new FileNotFoundException("Resource '" + resourceName.toString() + "' not found");
        }

        byte[] buffer = new byte[1024];
        int read = -1;
        File temp = File.createTempFile(libraryName, getLibraryFileSuffix(os));

        FileOutputStream fos = new FileOutputStream(temp);

        while ((read = in.read(buffer)) != -1) {
            fos.write(buffer, 0, read);
        }
        fos.close();
        in.close();

        System.load(temp.getAbsolutePath());
    }

    private final static native void swig_module_init();

    public final static native long VirgilVersion_asNumber();

    public final static native String VirgilVersion_asString();

    public final static native long VirgilVersion_majorVersion();

    public final static native long VirgilVersion_minorVersion();

    public final static native long VirgilVersion_patchVersion();

    public final static native String VirgilVersion_fullName();

    public final static native long new_VirgilVersion();

    public final static native void delete_VirgilVersion(long jarg1);

    public final static native boolean VirgilDataSource_hasData(long jarg1, VirgilDataSource jarg1_)
            throws java.io.IOException;

    public final static native byte[] VirgilDataSource_read(long jarg1, VirgilDataSource jarg1_)
            throws java.io.IOException;

    public final static native void delete_VirgilDataSource(long jarg1);

    public final static native long new_VirgilDataSource();

    public final static native void VirgilDataSource_director_connect(VirgilDataSource obj, long cptr, boolean mem_own,
            boolean weak_global);

    public final static native void VirgilDataSource_change_ownership(VirgilDataSource obj, long cptr,
            boolean take_or_release);

    public final static native boolean VirgilDataSink_isGood(long jarg1, VirgilDataSink jarg1_)
            throws java.io.IOException;

    public final static native void VirgilDataSink_write(long jarg1, VirgilDataSink jarg1_, byte[] jarg2)
            throws java.io.IOException;

    public final static native void delete_VirgilDataSink(long jarg1);

    public final static native long new_VirgilDataSink();

    public final static native void VirgilDataSink_director_connect(VirgilDataSink obj, long cptr, boolean mem_own,
            boolean weak_global);

    public final static native void VirgilDataSink_change_ownership(VirgilDataSink obj, long cptr,
            boolean take_or_release);

    public final static native byte[] VirgilAsn1Compatible_toAsn1(long jarg1, VirgilAsn1Compatible jarg1_);

    public final static native void VirgilAsn1Compatible_fromAsn1(long jarg1, VirgilAsn1Compatible jarg1_,
            byte[] jarg2);

    public final static native void delete_VirgilAsn1Compatible(long jarg1);

    public final static native long VirgilKeyPair_generate__SWIG_0(int jarg1, byte[] jarg2);

    public final static native long VirgilKeyPair_generate__SWIG_1(int jarg1);

    public final static native long VirgilKeyPair_generateRecommended__SWIG_0(byte[] jarg1);

    public final static native long VirgilKeyPair_generateRecommended__SWIG_1();

    public final static native long VirgilKeyPair_generateFrom__SWIG_0(long jarg1, VirgilKeyPair jarg1_, byte[] jarg2,
            byte[] jarg3);

    public final static native long VirgilKeyPair_generateFrom__SWIG_1(long jarg1, VirgilKeyPair jarg1_, byte[] jarg2);

    public final static native long VirgilKeyPair_generateFrom__SWIG_2(long jarg1, VirgilKeyPair jarg1_);

    public final static native boolean VirgilKeyPair_isKeyPairMatch__SWIG_0(byte[] jarg1, byte[] jarg2, byte[] jarg3);

    public final static native boolean VirgilKeyPair_isKeyPairMatch__SWIG_1(byte[] jarg1, byte[] jarg2);

    public final static native boolean VirgilKeyPair_checkPrivateKeyPassword(byte[] jarg1, byte[] jarg2);

    public final static native boolean VirgilKeyPair_isPrivateKeyEncrypted(byte[] jarg1);

    public final static native byte[] VirgilKeyPair_resetPrivateKeyPassword(byte[] jarg1, byte[] jarg2, byte[] jarg3);

    public final static native byte[] VirgilKeyPair_encryptPrivateKey(byte[] jarg1, byte[] jarg2);

    public final static native byte[] VirgilKeyPair_decryptPrivateKey(byte[] jarg1, byte[] jarg2);

    public final static native byte[] VirgilKeyPair_extractPublicKey(byte[] jarg1, byte[] jarg2);

    public final static native byte[] VirgilKeyPair_publicKeyToPEM(byte[] jarg1);

    public final static native byte[] VirgilKeyPair_publicKeyToDER(byte[] jarg1);

    public final static native byte[] VirgilKeyPair_privateKeyToPEM__SWIG_0(byte[] jarg1, byte[] jarg2);

    public final static native byte[] VirgilKeyPair_privateKeyToPEM__SWIG_1(byte[] jarg1);

    public final static native byte[] VirgilKeyPair_privateKeyToDER__SWIG_0(byte[] jarg1, byte[] jarg2);

    public final static native byte[] VirgilKeyPair_privateKeyToDER__SWIG_1(byte[] jarg1);

    public final static native long new_VirgilKeyPair__SWIG_0(byte[] jarg1, byte[] jarg2);

    public final static native byte[] VirgilKeyPair_publicKey(long jarg1, VirgilKeyPair jarg1_);

    public final static native byte[] VirgilKeyPair_privateKey(long jarg1, VirgilKeyPair jarg1_);

    public final static native long new_VirgilKeyPair__SWIG_1(long jarg1, VirgilKeyPair jarg1_);

    public final static native void delete_VirgilKeyPair(long jarg1);

    public final static native long new_VirgilAsn1Reader__SWIG_0();

    public final static native long new_VirgilAsn1Reader__SWIG_1(byte[] jarg1);

    public final static native void delete_VirgilAsn1Reader(long jarg1);

    public final static native void VirgilAsn1Reader_reset(long jarg1, VirgilAsn1Reader jarg1_, byte[] jarg2);

    public final static native int VirgilAsn1Reader_readInteger(long jarg1, VirgilAsn1Reader jarg1_);

    public final static native boolean VirgilAsn1Reader_readBool(long jarg1, VirgilAsn1Reader jarg1_);

    public final static native void VirgilAsn1Reader_readNull(long jarg1, VirgilAsn1Reader jarg1_);

    public final static native byte[] VirgilAsn1Reader_readOctetString(long jarg1, VirgilAsn1Reader jarg1_);

    public final static native byte[] VirgilAsn1Reader_readUTF8String(long jarg1, VirgilAsn1Reader jarg1_);

    public final static native byte[] VirgilAsn1Reader_readData(long jarg1, VirgilAsn1Reader jarg1_);

    public final static native long VirgilAsn1Reader_readContextTag(long jarg1, VirgilAsn1Reader jarg1_, short jarg2);

    public final static native String VirgilAsn1Reader_readOID(long jarg1, VirgilAsn1Reader jarg1_);

    public final static native long VirgilAsn1Reader_readSequence(long jarg1, VirgilAsn1Reader jarg1_);

    public final static native long VirgilAsn1Reader_readSet(long jarg1, VirgilAsn1Reader jarg1_);

    public final static native long new_VirgilAsn1Writer__SWIG_0();

    public final static native long new_VirgilAsn1Writer__SWIG_1(long jarg1);

    public final static native void delete_VirgilAsn1Writer(long jarg1);

    public final static native void VirgilAsn1Writer_reset__SWIG_0(long jarg1, VirgilAsn1Writer jarg1_);

    public final static native void VirgilAsn1Writer_reset__SWIG_1(long jarg1, VirgilAsn1Writer jarg1_, long jarg2);

    public final static native byte[] VirgilAsn1Writer_finish(long jarg1, VirgilAsn1Writer jarg1_);

    public final static native long VirgilAsn1Writer_writeInteger(long jarg1, VirgilAsn1Writer jarg1_, int jarg2);

    public final static native long VirgilAsn1Writer_writeBool(long jarg1, VirgilAsn1Writer jarg1_, boolean jarg2);

    public final static native long VirgilAsn1Writer_writeNull(long jarg1, VirgilAsn1Writer jarg1_);

    public final static native long VirgilAsn1Writer_writeOctetString(long jarg1, VirgilAsn1Writer jarg1_,
            byte[] jarg2);

    public final static native long VirgilAsn1Writer_writeUTF8String(long jarg1, VirgilAsn1Writer jarg1_, byte[] jarg2);

    public final static native long VirgilAsn1Writer_writeContextTag(long jarg1, VirgilAsn1Writer jarg1_, short jarg2,
            long jarg3);

    public final static native long VirgilAsn1Writer_writeData(long jarg1, VirgilAsn1Writer jarg1_, byte[] jarg2);

    public final static native long VirgilAsn1Writer_writeOID(long jarg1, VirgilAsn1Writer jarg1_, String jarg2);

    public final static native long VirgilAsn1Writer_writeSequence(long jarg1, VirgilAsn1Writer jarg1_, long jarg2);

    public final static native long VirgilAsn1Writer_writeSet(long jarg1, VirgilAsn1Writer jarg1_, long jarg2);

    public final static native void VirgilCMSKeyTransRecipient_recipientIdentifier_set(long jarg1,
            VirgilCMSKeyTransRecipient jarg1_, byte[] jarg2);

    public final static native byte[] VirgilCMSKeyTransRecipient_recipientIdentifier_get(long jarg1,
            VirgilCMSKeyTransRecipient jarg1_);

    public final static native void VirgilCMSKeyTransRecipient_keyEncryptionAlgorithm_set(long jarg1,
            VirgilCMSKeyTransRecipient jarg1_, byte[] jarg2);

    public final static native byte[] VirgilCMSKeyTransRecipient_keyEncryptionAlgorithm_get(long jarg1,
            VirgilCMSKeyTransRecipient jarg1_);

    public final static native void VirgilCMSKeyTransRecipient_encryptedKey_set(long jarg1,
            VirgilCMSKeyTransRecipient jarg1_, byte[] jarg2);

    public final static native byte[] VirgilCMSKeyTransRecipient_encryptedKey_get(long jarg1,
            VirgilCMSKeyTransRecipient jarg1_);

    public final static native long new_VirgilCMSKeyTransRecipient__SWIG_0();

    public final static native long new_VirgilCMSKeyTransRecipient__SWIG_1(long jarg1,
            VirgilCMSKeyTransRecipient jarg1_);

    public final static native void delete_VirgilCMSKeyTransRecipient(long jarg1);

    public final static native void VirgilCMSPasswordRecipient_keyDerivationAlgorithm_set(long jarg1,
            VirgilCMSPasswordRecipient jarg1_, byte[] jarg2);

    public final static native byte[] VirgilCMSPasswordRecipient_keyDerivationAlgorithm_get(long jarg1,
            VirgilCMSPasswordRecipient jarg1_);

    public final static native void VirgilCMSPasswordRecipient_keyEncryptionAlgorithm_set(long jarg1,
            VirgilCMSPasswordRecipient jarg1_, byte[] jarg2);

    public final static native byte[] VirgilCMSPasswordRecipient_keyEncryptionAlgorithm_get(long jarg1,
            VirgilCMSPasswordRecipient jarg1_);

    public final static native void VirgilCMSPasswordRecipient_encryptedKey_set(long jarg1,
            VirgilCMSPasswordRecipient jarg1_, byte[] jarg2);

    public final static native byte[] VirgilCMSPasswordRecipient_encryptedKey_get(long jarg1,
            VirgilCMSPasswordRecipient jarg1_);

    public final static native long new_VirgilCMSPasswordRecipient__SWIG_0();

    public final static native long new_VirgilCMSPasswordRecipient__SWIG_1(long jarg1,
            VirgilCMSPasswordRecipient jarg1_);

    public final static native void delete_VirgilCMSPasswordRecipient(long jarg1);

    public final static native void VirgilCMSEncryptedContent_contentEncryptionAlgorithm_set(long jarg1,
            VirgilCMSEncryptedContent jarg1_, byte[] jarg2);

    public final static native byte[] VirgilCMSEncryptedContent_contentEncryptionAlgorithm_get(long jarg1,
            VirgilCMSEncryptedContent jarg1_);

    public final static native void VirgilCMSEncryptedContent_encryptedContent_set(long jarg1,
            VirgilCMSEncryptedContent jarg1_, byte[] jarg2);

    public final static native byte[] VirgilCMSEncryptedContent_encryptedContent_get(long jarg1,
            VirgilCMSEncryptedContent jarg1_);

    public final static native long new_VirgilCMSEncryptedContent__SWIG_0();

    public final static native long new_VirgilCMSEncryptedContent__SWIG_1(long jarg1, VirgilCMSEncryptedContent jarg1_);

    public final static native void delete_VirgilCMSEncryptedContent(long jarg1);

    public final static native void VirgilCMSEnvelopedData_keyTransRecipients_set(long jarg1,
            VirgilCMSEnvelopedData jarg1_, long jarg2);

    public final static native long VirgilCMSEnvelopedData_keyTransRecipients_get(long jarg1,
            VirgilCMSEnvelopedData jarg1_);

    public final static native void VirgilCMSEnvelopedData_passwordRecipients_set(long jarg1,
            VirgilCMSEnvelopedData jarg1_, long jarg2);

    public final static native long VirgilCMSEnvelopedData_passwordRecipients_get(long jarg1,
            VirgilCMSEnvelopedData jarg1_);

    public final static native void VirgilCMSEnvelopedData_encryptedContent_set(long jarg1,
            VirgilCMSEnvelopedData jarg1_, long jarg2, VirgilCMSEncryptedContent jarg2_);

    public final static native long VirgilCMSEnvelopedData_encryptedContent_get(long jarg1,
            VirgilCMSEnvelopedData jarg1_);

    public final static native long new_VirgilCMSEnvelopedData__SWIG_0();

    public final static native long new_VirgilCMSEnvelopedData__SWIG_1(long jarg1, VirgilCMSEnvelopedData jarg1_);

    public final static native void delete_VirgilCMSEnvelopedData(long jarg1);

    public final static native int VirgilCMSContent_Type_Data_get();

    public final static native void VirgilCMSContent_contentType_set(long jarg1, VirgilCMSContent jarg1_, int jarg2);

    public final static native int VirgilCMSContent_contentType_get(long jarg1, VirgilCMSContent jarg1_);

    public final static native void VirgilCMSContent_content_set(long jarg1, VirgilCMSContent jarg1_, byte[] jarg2);

    public final static native byte[] VirgilCMSContent_content_get(long jarg1, VirgilCMSContent jarg1_);

    public final static native long new_VirgilCMSContent__SWIG_0();

    public final static native long new_VirgilCMSContent__SWIG_1(long jarg1, VirgilCMSContent jarg1_);

    public final static native void delete_VirgilCMSContent(long jarg1);

    public final static native void VirgilCMSContentInfo_cmsContent_set(long jarg1, VirgilCMSContentInfo jarg1_,
            long jarg2, VirgilCMSContent jarg2_);

    public final static native long VirgilCMSContentInfo_cmsContent_get(long jarg1, VirgilCMSContentInfo jarg1_);

    public final static native void VirgilCMSContentInfo_customParams_set(long jarg1, VirgilCMSContentInfo jarg1_,
            long jarg2, VirgilCustomParams jarg2_);

    public final static native long VirgilCMSContentInfo_customParams_get(long jarg1, VirgilCMSContentInfo jarg1_);

    public final static native long VirgilCMSContentInfo_defineSize(byte[] jarg1);

    public final static native long new_VirgilCMSContentInfo__SWIG_0();

    public final static native long new_VirgilCMSContentInfo__SWIG_1(long jarg1, VirgilCMSContentInfo jarg1_);

    public final static native void delete_VirgilCMSContentInfo(long jarg1);

    public final static native long new_VirgilHash__SWIG_0();

    public final static native long new_VirgilHash__SWIG_1(int jarg1);

    public final static native long new_VirgilHash__SWIG_2(String jarg1);

    public final static native String VirgilHash_name(long jarg1, VirgilHash jarg1_);

    public final static native int VirgilHash_algorithm(long jarg1, VirgilHash jarg1_);

    public final static native int VirgilHash_type(long jarg1, VirgilHash jarg1_);

    public final static native long VirgilHash_size(long jarg1, VirgilHash jarg1_);

    public final static native byte[] VirgilHash_hash(long jarg1, VirgilHash jarg1_, byte[] jarg2);

    public final static native void VirgilHash_start(long jarg1, VirgilHash jarg1_);

    public final static native void VirgilHash_update(long jarg1, VirgilHash jarg1_, byte[] jarg2);

    public final static native byte[] VirgilHash_finish(long jarg1, VirgilHash jarg1_);

    public final static native byte[] VirgilHash_hmac(long jarg1, VirgilHash jarg1_, byte[] jarg2, byte[] jarg3);

    public final static native void VirgilHash_hmacStart(long jarg1, VirgilHash jarg1_, byte[] jarg2);

    public final static native void VirgilHash_hmacReset(long jarg1, VirgilHash jarg1_);

    public final static native void VirgilHash_hmacUpdate(long jarg1, VirgilHash jarg1_, byte[] jarg2);

    public final static native byte[] VirgilHash_hmacFinish(long jarg1, VirgilHash jarg1_);

    public final static native void delete_VirgilHash(long jarg1);

    public final static native long new_VirgilHash__SWIG_3(long jarg1, VirgilHash jarg1_);

    public final static native long new_VirgilKDF__SWIG_0();

    public final static native long new_VirgilKDF__SWIG_1(int jarg1);

    public final static native long new_VirgilKDF__SWIG_2(String jarg1);

    public final static native String VirgilKDF_name(long jarg1, VirgilKDF jarg1_);

    public final static native byte[] VirgilKDF_derive(long jarg1, VirgilKDF jarg1_, byte[] jarg2, long jarg3);

    public final static native void delete_VirgilKDF(long jarg1);

    public final static native int VirgilSymmetricCipher_Padding_PKCS7_get();

    public final static native long new_VirgilSymmetricCipher__SWIG_0();

    public final static native long new_VirgilSymmetricCipher__SWIG_1(int jarg1);

    public final static native long new_VirgilSymmetricCipher__SWIG_2(String jarg1);

    public final static native String VirgilSymmetricCipher_name(long jarg1, VirgilSymmetricCipher jarg1_);

    public final static native long VirgilSymmetricCipher_blockSize(long jarg1, VirgilSymmetricCipher jarg1_);

    public final static native long VirgilSymmetricCipher_ivSize(long jarg1, VirgilSymmetricCipher jarg1_);

    public final static native long VirgilSymmetricCipher_keySize(long jarg1, VirgilSymmetricCipher jarg1_);

    public final static native long VirgilSymmetricCipher_keyLength(long jarg1, VirgilSymmetricCipher jarg1_);

    public final static native long VirgilSymmetricCipher_authTagLength(long jarg1, VirgilSymmetricCipher jarg1_);

    public final static native boolean VirgilSymmetricCipher_isEncryptionMode(long jarg1, VirgilSymmetricCipher jarg1_);

    public final static native boolean VirgilSymmetricCipher_isDecryptionMode(long jarg1, VirgilSymmetricCipher jarg1_);

    public final static native boolean VirgilSymmetricCipher_isAuthMode(long jarg1, VirgilSymmetricCipher jarg1_);

    public final static native boolean VirgilSymmetricCipher_isSupportPadding(long jarg1, VirgilSymmetricCipher jarg1_);

    public final static native byte[] VirgilSymmetricCipher_iv(long jarg1, VirgilSymmetricCipher jarg1_);

    public final static native void VirgilSymmetricCipher_setEncryptionKey(long jarg1, VirgilSymmetricCipher jarg1_,
            byte[] jarg2);

    public final static native void VirgilSymmetricCipher_setDecryptionKey(long jarg1, VirgilSymmetricCipher jarg1_,
            byte[] jarg2);

    public final static native void VirgilSymmetricCipher_setPadding(long jarg1, VirgilSymmetricCipher jarg1_,
            int jarg2);

    public final static native void VirgilSymmetricCipher_setIV(long jarg1, VirgilSymmetricCipher jarg1_, byte[] jarg2);

    public final static native void VirgilSymmetricCipher_setAuthData(long jarg1, VirgilSymmetricCipher jarg1_,
            byte[] jarg2);

    public final static native void VirgilSymmetricCipher_reset(long jarg1, VirgilSymmetricCipher jarg1_);

    public final static native void VirgilSymmetricCipher_clear(long jarg1, VirgilSymmetricCipher jarg1_);

    public final static native byte[] VirgilSymmetricCipher_crypt(long jarg1, VirgilSymmetricCipher jarg1_,
            byte[] jarg2, byte[] jarg3);

    public final static native byte[] VirgilSymmetricCipher_update(long jarg1, VirgilSymmetricCipher jarg1_,
            byte[] jarg2);

    public final static native byte[] VirgilSymmetricCipher_finish(long jarg1, VirgilSymmetricCipher jarg1_);

    public final static native void delete_VirgilSymmetricCipher(long jarg1);

    public final static native long new_VirgilAsymmetricCipher();

    public final static native long VirgilAsymmetricCipher_keySize(long jarg1, VirgilAsymmetricCipher jarg1_);

    public final static native long VirgilAsymmetricCipher_keyLength(long jarg1, VirgilAsymmetricCipher jarg1_);

    public final static native boolean VirgilAsymmetricCipher_isKeyPairMatch__SWIG_0(byte[] jarg1, byte[] jarg2,
            byte[] jarg3);

    public final static native boolean VirgilAsymmetricCipher_isKeyPairMatch__SWIG_1(byte[] jarg1, byte[] jarg2);

    public final static native boolean VirgilAsymmetricCipher_isPublicKeyValid(byte[] jarg1);

    public final static native void VirgilAsymmetricCipher_checkPublicKey(byte[] jarg1);

    public final static native boolean VirgilAsymmetricCipher_checkPrivateKeyPassword(byte[] jarg1, byte[] jarg2);

    public final static native boolean VirgilAsymmetricCipher_isPrivateKeyEncrypted(byte[] jarg1);

    public final static native void VirgilAsymmetricCipher_setPrivateKey__SWIG_0(long jarg1,
            VirgilAsymmetricCipher jarg1_, byte[] jarg2, byte[] jarg3);

    public final static native void VirgilAsymmetricCipher_setPrivateKey__SWIG_1(long jarg1,
            VirgilAsymmetricCipher jarg1_, byte[] jarg2);

    public final static native void VirgilAsymmetricCipher_setPublicKey(long jarg1, VirgilAsymmetricCipher jarg1_,
            byte[] jarg2);

    public final static native void VirgilAsymmetricCipher_genKeyPair(long jarg1, VirgilAsymmetricCipher jarg1_,
            int jarg2);

    public final static native void VirgilAsymmetricCipher_genKeyPairFrom(long jarg1, VirgilAsymmetricCipher jarg1_,
            long jarg2, VirgilAsymmetricCipher jarg2_);

    public final static native byte[] VirgilAsymmetricCipher_computeShared(long jarg1, VirgilAsymmetricCipher jarg1_,
            long jarg2, VirgilAsymmetricCipher jarg2_);

    public final static native byte[] VirgilAsymmetricCipher_exportPrivateKeyToDER__SWIG_0(long jarg1,
            VirgilAsymmetricCipher jarg1_, byte[] jarg2);

    public final static native byte[] VirgilAsymmetricCipher_exportPrivateKeyToDER__SWIG_1(long jarg1,
            VirgilAsymmetricCipher jarg1_);

    public final static native byte[] VirgilAsymmetricCipher_exportPublicKeyToDER(long jarg1,
            VirgilAsymmetricCipher jarg1_);

    public final static native byte[] VirgilAsymmetricCipher_exportPrivateKeyToPEM__SWIG_0(long jarg1,
            VirgilAsymmetricCipher jarg1_, byte[] jarg2);

    public final static native byte[] VirgilAsymmetricCipher_exportPrivateKeyToPEM__SWIG_1(long jarg1,
            VirgilAsymmetricCipher jarg1_);

    public final static native byte[] VirgilAsymmetricCipher_exportPublicKeyToPEM(long jarg1,
            VirgilAsymmetricCipher jarg1_);

    public final static native int VirgilAsymmetricCipher_getKeyType(long jarg1, VirgilAsymmetricCipher jarg1_);

    public final static native void VirgilAsymmetricCipher_setKeyType(long jarg1, VirgilAsymmetricCipher jarg1_,
            int jarg2);

    public final static native byte[] VirgilAsymmetricCipher_getPublicKeyBits(long jarg1,
            VirgilAsymmetricCipher jarg1_);

    public final static native void VirgilAsymmetricCipher_setPublicKeyBits(long jarg1, VirgilAsymmetricCipher jarg1_,
            byte[] jarg2);

    public final static native byte[] VirgilAsymmetricCipher_encrypt(long jarg1, VirgilAsymmetricCipher jarg1_,
            byte[] jarg2);

    public final static native byte[] VirgilAsymmetricCipher_decrypt(long jarg1, VirgilAsymmetricCipher jarg1_,
            byte[] jarg2);

    public final static native byte[] VirgilAsymmetricCipher_sign(long jarg1, VirgilAsymmetricCipher jarg1_,
            byte[] jarg2, int jarg3);

    public final static native boolean VirgilAsymmetricCipher_verify(long jarg1, VirgilAsymmetricCipher jarg1_,
            byte[] jarg2, byte[] jarg3, int jarg4);

    public final static native void delete_VirgilAsymmetricCipher(long jarg1);

    public final static native long VirgilPBE_kIterationCountMin_get();

    public final static native long new_VirgilPBE__SWIG_0();

    public final static native long new_VirgilPBE__SWIG_1(int jarg1, byte[] jarg2, long jarg3);

    public final static native long new_VirgilPBE__SWIG_2(int jarg1, byte[] jarg2);

    public final static native byte[] VirgilPBE_encrypt(long jarg1, VirgilPBE jarg1_, byte[] jarg2, byte[] jarg3);

    public final static native byte[] VirgilPBE_decrypt(long jarg1, VirgilPBE jarg1_, byte[] jarg2, byte[] jarg3);

    public final static native void delete_VirgilPBE(long jarg1);

    public final static native long new_VirgilHKDF(int jarg1);

    public final static native byte[] VirgilHKDF_derive(long jarg1, VirgilHKDF jarg1_, byte[] jarg2, byte[] jarg3,
            byte[] jarg4, long jarg5);

    public final static native void delete_VirgilHKDF(long jarg1);

    public final static native String VirgilBase64_encode(byte[] jarg1);

    public final static native byte[] VirgilBase64_decode(String jarg1);

    public final static native void delete_VirgilBase64(long jarg1);

    public final static native long VirgilPBKDF_kIterationCount_Default_get();

    public final static native long new_VirgilPBKDF__SWIG_0();

    public final static native long new_VirgilPBKDF__SWIG_1(byte[] jarg1, long jarg2);

    public final static native long new_VirgilPBKDF__SWIG_2(byte[] jarg1);

    public final static native byte[] VirgilPBKDF_getSalt(long jarg1, VirgilPBKDF jarg1_);

    public final static native long VirgilPBKDF_getIterationCount(long jarg1, VirgilPBKDF jarg1_);

    public final static native void VirgilPBKDF_setAlgorithm(long jarg1, VirgilPBKDF jarg1_, int jarg2);

    public final static native int VirgilPBKDF_getAlgorithm(long jarg1, VirgilPBKDF jarg1_);

    public final static native void VirgilPBKDF_setHashAlgorithm(long jarg1, VirgilPBKDF jarg1_, int jarg2);

    public final static native int VirgilPBKDF_getHashAlgorithm(long jarg1, VirgilPBKDF jarg1_);

    public final static native void VirgilPBKDF_enableRecommendationsCheck(long jarg1, VirgilPBKDF jarg1_);

    public final static native void VirgilPBKDF_disableRecommendationsCheck(long jarg1, VirgilPBKDF jarg1_);

    public final static native byte[] VirgilPBKDF_derive__SWIG_0(long jarg1, VirgilPBKDF jarg1_, byte[] jarg2,
            long jarg3);

    public final static native byte[] VirgilPBKDF_derive__SWIG_1(long jarg1, VirgilPBKDF jarg1_, byte[] jarg2);

    public final static native void delete_VirgilPBKDF(long jarg1);

    public final static native long new_VirgilRandom__SWIG_0(String jarg1);

    public final static native byte[] VirgilRandom_randomize__SWIG_0(long jarg1, VirgilRandom jarg1_, long jarg2);

    public final static native long VirgilRandom_randomize__SWIG_1(long jarg1, VirgilRandom jarg1_);

    public final static native long VirgilRandom_randomize__SWIG_2(long jarg1, VirgilRandom jarg1_, long jarg2,
            long jarg3);

    public final static native void delete_VirgilRandom(long jarg1);

    public final static native long new_VirgilRandom__SWIG_1(long jarg1, VirgilRandom jarg1_);

    public final static native boolean VirgilCustomParams_isEmpty(long jarg1, VirgilCustomParams jarg1_);

    public final static native void VirgilCustomParams_setInteger(long jarg1, VirgilCustomParams jarg1_, byte[] jarg2,
            int jarg3);

    public final static native int VirgilCustomParams_getInteger(long jarg1, VirgilCustomParams jarg1_, byte[] jarg2);

    public final static native void VirgilCustomParams_removeInteger(long jarg1, VirgilCustomParams jarg1_,
            byte[] jarg2);

    public final static native void VirgilCustomParams_setString(long jarg1, VirgilCustomParams jarg1_, byte[] jarg2,
            byte[] jarg3);

    public final static native byte[] VirgilCustomParams_getString(long jarg1, VirgilCustomParams jarg1_, byte[] jarg2);

    public final static native void VirgilCustomParams_removeString(long jarg1, VirgilCustomParams jarg1_,
            byte[] jarg2);

    public final static native void VirgilCustomParams_setData(long jarg1, VirgilCustomParams jarg1_, byte[] jarg2,
            byte[] jarg3);

    public final static native byte[] VirgilCustomParams_getData(long jarg1, VirgilCustomParams jarg1_, byte[] jarg2);

    public final static native void VirgilCustomParams_removeData(long jarg1, VirgilCustomParams jarg1_, byte[] jarg2);

    public final static native void VirgilCustomParams_clear(long jarg1, VirgilCustomParams jarg1_);

    public final static native long new_VirgilCustomParams__SWIG_0();

    public final static native long new_VirgilCustomParams__SWIG_1(long jarg1, VirgilCustomParams jarg1_);

    public final static native void delete_VirgilCustomParams(long jarg1);

    public final static native long new_VirgilCipherBase();

    public final static native void VirgilCipherBase_addKeyRecipient(long jarg1, VirgilCipherBase jarg1_, byte[] jarg2,
            byte[] jarg3);

    public final static native void VirgilCipherBase_removeKeyRecipient(long jarg1, VirgilCipherBase jarg1_,
            byte[] jarg2);

    public final static native boolean VirgilCipherBase_keyRecipientExists(long jarg1, VirgilCipherBase jarg1_,
            byte[] jarg2);

    public final static native void VirgilCipherBase_addPasswordRecipient(long jarg1, VirgilCipherBase jarg1_,
            byte[] jarg2);

    public final static native void VirgilCipherBase_removePasswordRecipient(long jarg1, VirgilCipherBase jarg1_,
            byte[] jarg2);

    public final static native boolean VirgilCipherBase_passwordRecipientExists(long jarg1, VirgilCipherBase jarg1_,
            byte[] jarg2);

    public final static native void VirgilCipherBase_removeAllRecipients(long jarg1, VirgilCipherBase jarg1_);

    public final static native byte[] VirgilCipherBase_getContentInfo(long jarg1, VirgilCipherBase jarg1_);

    public final static native void VirgilCipherBase_setContentInfo(long jarg1, VirgilCipherBase jarg1_, byte[] jarg2);

    public final static native long VirgilCipherBase_defineContentInfoSize(byte[] jarg1);

    public final static native long VirgilCipherBase_customParams__SWIG_0(long jarg1, VirgilCipherBase jarg1_);

    public final static native byte[] VirgilCipherBase_computeShared__SWIG_0(byte[] jarg1, byte[] jarg2, byte[] jarg3);

    public final static native byte[] VirgilCipherBase_computeShared__SWIG_1(byte[] jarg1, byte[] jarg2);

    public final static native void delete_VirgilCipherBase(long jarg1);

    public final static native byte[] VirgilCipher_encrypt__SWIG_0(long jarg1, VirgilCipher jarg1_, byte[] jarg2,
            boolean jarg3);

    public final static native byte[] VirgilCipher_encrypt__SWIG_1(long jarg1, VirgilCipher jarg1_, byte[] jarg2);

    public final static native byte[] VirgilCipher_decryptWithKey__SWIG_0(long jarg1, VirgilCipher jarg1_, byte[] jarg2,
            byte[] jarg3, byte[] jarg4, byte[] jarg5);

    public final static native byte[] VirgilCipher_decryptWithKey__SWIG_1(long jarg1, VirgilCipher jarg1_, byte[] jarg2,
            byte[] jarg3, byte[] jarg4);

    public final static native byte[] VirgilCipher_decryptWithPassword(long jarg1, VirgilCipher jarg1_, byte[] jarg2,
            byte[] jarg3);

    public final static native long new_VirgilCipher();

    public final static native void delete_VirgilCipher(long jarg1);

    public final static native long VirgilChunkCipher_kPreferredChunkSize_get();

    public final static native void VirgilChunkCipher_encrypt__SWIG_0(long jarg1, VirgilChunkCipher jarg1_, long jarg2,
            VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, boolean jarg4, long jarg5);

    public final static native void VirgilChunkCipher_encrypt__SWIG_1(long jarg1, VirgilChunkCipher jarg1_, long jarg2,
            VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, boolean jarg4);

    public final static native void VirgilChunkCipher_encrypt__SWIG_2(long jarg1, VirgilChunkCipher jarg1_, long jarg2,
            VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_);

    public final static native void VirgilChunkCipher_decryptWithKey__SWIG_0(long jarg1, VirgilChunkCipher jarg1_,
            long jarg2, VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, byte[] jarg4, byte[] jarg5,
            byte[] jarg6);

    public final static native void VirgilChunkCipher_decryptWithKey__SWIG_1(long jarg1, VirgilChunkCipher jarg1_,
            long jarg2, VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, byte[] jarg4, byte[] jarg5);

    public final static native void VirgilChunkCipher_decryptWithPassword(long jarg1, VirgilChunkCipher jarg1_,
            long jarg2, VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, byte[] jarg4);

    public final static native long new_VirgilChunkCipher();

    public final static native void delete_VirgilChunkCipher(long jarg1);

    public final static native long new_VirgilSignerBase__SWIG_0(int jarg1);

    public final static native long new_VirgilSignerBase__SWIG_1();

    public final static native int VirgilSignerBase_getHashAlgorithm(long jarg1, VirgilSignerBase jarg1_);

    public final static native byte[] VirgilSignerBase_signHash__SWIG_0(long jarg1, VirgilSignerBase jarg1_,
            byte[] jarg2, byte[] jarg3, byte[] jarg4);

    public final static native byte[] VirgilSignerBase_signHash__SWIG_1(long jarg1, VirgilSignerBase jarg1_,
            byte[] jarg2, byte[] jarg3);

    public final static native boolean VirgilSignerBase_verifyHash(long jarg1, VirgilSignerBase jarg1_, byte[] jarg2,
            byte[] jarg3, byte[] jarg4);

    public final static native void delete_VirgilSignerBase(long jarg1);

    public final static native byte[] VirgilSigner_sign__SWIG_0(long jarg1, VirgilSigner jarg1_, byte[] jarg2,
            byte[] jarg3, byte[] jarg4);

    public final static native byte[] VirgilSigner_sign__SWIG_1(long jarg1, VirgilSigner jarg1_, byte[] jarg2,
            byte[] jarg3);

    public final static native boolean VirgilSigner_verify(long jarg1, VirgilSigner jarg1_, byte[] jarg2, byte[] jarg3,
            byte[] jarg4);

    public final static native long new_VirgilSigner();

    public final static native void delete_VirgilSigner(long jarg1);

    public final static native byte[] VirgilStreamSigner_sign__SWIG_0(long jarg1, VirgilStreamSigner jarg1_, long jarg2,
            VirgilDataSource jarg2_, byte[] jarg3, byte[] jarg4);

    public final static native byte[] VirgilStreamSigner_sign__SWIG_1(long jarg1, VirgilStreamSigner jarg1_, long jarg2,
            VirgilDataSource jarg2_, byte[] jarg3);

    public final static native boolean VirgilStreamSigner_verify(long jarg1, VirgilStreamSigner jarg1_, long jarg2,
            VirgilDataSource jarg2_, byte[] jarg3, byte[] jarg4);

    public final static native long new_VirgilStreamSigner();

    public final static native void delete_VirgilStreamSigner(long jarg1);

    public final static native void VirgilStreamCipher_encrypt__SWIG_0(long jarg1, VirgilStreamCipher jarg1_,
            long jarg2, VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, boolean jarg4);

    public final static native void VirgilStreamCipher_encrypt__SWIG_1(long jarg1, VirgilStreamCipher jarg1_,
            long jarg2, VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_);

    public final static native void VirgilStreamCipher_decryptWithKey__SWIG_0(long jarg1, VirgilStreamCipher jarg1_,
            long jarg2, VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, byte[] jarg4, byte[] jarg5,
            byte[] jarg6);

    public final static native void VirgilStreamCipher_decryptWithKey__SWIG_1(long jarg1, VirgilStreamCipher jarg1_,
            long jarg2, VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, byte[] jarg4, byte[] jarg5);

    public final static native void VirgilStreamCipher_decryptWithPassword(long jarg1, VirgilStreamCipher jarg1_,
            long jarg2, VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, byte[] jarg4);

    public final static native long new_VirgilStreamCipher();

    public final static native void delete_VirgilStreamCipher(long jarg1);

    public final static native int VirgilTinyCipher_Min_get();

    public final static native int VirgilTinyCipher_Short_SMS_get();

    public final static native int VirgilTinyCipher_Long_SMS_get();

    public final static native long new_VirgilTinyCipher__SWIG_0(long jarg1);

    public final static native long new_VirgilTinyCipher__SWIG_1();

    public final static native void VirgilTinyCipher_reset(long jarg1, VirgilTinyCipher jarg1_);

    public final static native void VirgilTinyCipher_encrypt(long jarg1, VirgilTinyCipher jarg1_, byte[] jarg2,
            byte[] jarg3);

    public final static native void VirgilTinyCipher_encryptAndSign__SWIG_0(long jarg1, VirgilTinyCipher jarg1_,
            byte[] jarg2, byte[] jarg3, byte[] jarg4, byte[] jarg5);

    public final static native void VirgilTinyCipher_encryptAndSign__SWIG_1(long jarg1, VirgilTinyCipher jarg1_,
            byte[] jarg2, byte[] jarg3, byte[] jarg4);

    public final static native long VirgilTinyCipher_getPackageCount(long jarg1, VirgilTinyCipher jarg1_);

    public final static native byte[] VirgilTinyCipher_getPackage(long jarg1, VirgilTinyCipher jarg1_, long jarg2);

    public final static native void VirgilTinyCipher_addPackage(long jarg1, VirgilTinyCipher jarg1_, byte[] jarg2);

    public final static native boolean VirgilTinyCipher_isPackagesAccumulated(long jarg1, VirgilTinyCipher jarg1_);

    public final static native byte[] VirgilTinyCipher_decrypt__SWIG_0(long jarg1, VirgilTinyCipher jarg1_,
            byte[] jarg2, byte[] jarg3);

    public final static native byte[] VirgilTinyCipher_decrypt__SWIG_1(long jarg1, VirgilTinyCipher jarg1_,
            byte[] jarg2);

    public final static native byte[] VirgilTinyCipher_verifyAndDecrypt__SWIG_0(long jarg1, VirgilTinyCipher jarg1_,
            byte[] jarg2, byte[] jarg3, byte[] jarg4);

    public final static native byte[] VirgilTinyCipher_verifyAndDecrypt__SWIG_1(long jarg1, VirgilTinyCipher jarg1_,
            byte[] jarg2, byte[] jarg3);

    public final static native void delete_VirgilTinyCipher(long jarg1);

    public final static native byte[] VirgilByteArrayUtils_jsonToBytes(String jarg1);

    public final static native byte[] VirgilByteArrayUtils_stringToBytes(String jarg1);

    public final static native String VirgilByteArrayUtils_bytesToString(byte[] jarg1);

    public final static native byte[] VirgilByteArrayUtils_hexToBytes(String jarg1);

    public final static native String VirgilByteArrayUtils_bytesToHex__SWIG_0(byte[] jarg1, boolean jarg2);

    public final static native String VirgilByteArrayUtils_bytesToHex__SWIG_1(byte[] jarg1);

    public final static native void delete_VirgilByteArrayUtils(long jarg1);

    public final static native long new_VirgilPFSEncryptedMessage(byte[] jarg1, byte[] jarg2, byte[] jarg3);

    public final static native byte[] VirgilPFSEncryptedMessage_getSessionIdentifier(long jarg1,
            VirgilPFSEncryptedMessage jarg1_);

    public final static native byte[] VirgilPFSEncryptedMessage_getSalt(long jarg1, VirgilPFSEncryptedMessage jarg1_);

    public final static native byte[] VirgilPFSEncryptedMessage_getCipherText(long jarg1,
            VirgilPFSEncryptedMessage jarg1_);

    public final static native void delete_VirgilPFSEncryptedMessage(long jarg1);

    public final static native long new_VirgilPFSPublicKey__SWIG_0(byte[] jarg1);

    public final static native long new_VirgilPFSPublicKey__SWIG_1();

    public final static native boolean VirgilPFSPublicKey_isEmpty(long jarg1, VirgilPFSPublicKey jarg1_);

    public final static native byte[] VirgilPFSPublicKey_getKey(long jarg1, VirgilPFSPublicKey jarg1_);

    public final static native void delete_VirgilPFSPublicKey(long jarg1);

    public final static native long new_VirgilPFSPrivateKey__SWIG_0(byte[] jarg1, byte[] jarg2);

    public final static native long new_VirgilPFSPrivateKey__SWIG_1(byte[] jarg1);

    public final static native long new_VirgilPFSPrivateKey__SWIG_2();

    public final static native boolean VirgilPFSPrivateKey_isEmpty(long jarg1, VirgilPFSPrivateKey jarg1_);

    public final static native byte[] VirgilPFSPrivateKey_getKey(long jarg1, VirgilPFSPrivateKey jarg1_);

    public final static native byte[] VirgilPFSPrivateKey_getPassword(long jarg1, VirgilPFSPrivateKey jarg1_);

    public final static native long new_VirgilPFSPrivateKey__SWIG_3(long jarg1, VirgilPFSPrivateKey jarg1_);

    public final static native void delete_VirgilPFSPrivateKey(long jarg1);

    public final static native long new_VirgilPFSInitiatorPublicInfo(long jarg1, VirgilPFSPublicKey jarg1_, long jarg2,
            VirgilPFSPublicKey jarg2_);

    public final static native long VirgilPFSInitiatorPublicInfo_getIdentityPublicKey(long jarg1,
            VirgilPFSInitiatorPublicInfo jarg1_);

    public final static native long VirgilPFSInitiatorPublicInfo_getEphemeralPublicKey(long jarg1,
            VirgilPFSInitiatorPublicInfo jarg1_);

    public final static native void delete_VirgilPFSInitiatorPublicInfo(long jarg1);

    public final static native long new_VirgilPFSInitiatorPrivateInfo(long jarg1, VirgilPFSPrivateKey jarg1_,
            long jarg2, VirgilPFSPrivateKey jarg2_);

    public final static native long VirgilPFSInitiatorPrivateInfo_getIdentityPrivateKey(long jarg1,
            VirgilPFSInitiatorPrivateInfo jarg1_);

    public final static native long VirgilPFSInitiatorPrivateInfo_getEphemeralPrivateKey(long jarg1,
            VirgilPFSInitiatorPrivateInfo jarg1_);

    public final static native void delete_VirgilPFSInitiatorPrivateInfo(long jarg1);

    public final static native long new_VirgilPFSResponderPublicInfo__SWIG_0(long jarg1, VirgilPFSPublicKey jarg1_,
            long jarg2, VirgilPFSPublicKey jarg2_, long jarg3, VirgilPFSPublicKey jarg3_);

    public final static native long new_VirgilPFSResponderPublicInfo__SWIG_1(long jarg1, VirgilPFSPublicKey jarg1_,
            long jarg2, VirgilPFSPublicKey jarg2_);

    public final static native long VirgilPFSResponderPublicInfo_getIdentityPublicKey(long jarg1,
            VirgilPFSResponderPublicInfo jarg1_);

    public final static native long VirgilPFSResponderPublicInfo_getLongTermPublicKey(long jarg1,
            VirgilPFSResponderPublicInfo jarg1_);

    public final static native long VirgilPFSResponderPublicInfo_getOneTimePublicKey(long jarg1,
            VirgilPFSResponderPublicInfo jarg1_);

    public final static native void delete_VirgilPFSResponderPublicInfo(long jarg1);

    public final static native long new_VirgilPFSResponderPrivateInfo__SWIG_0(long jarg1, VirgilPFSPrivateKey jarg1_,
            long jarg2, VirgilPFSPrivateKey jarg2_, long jarg3, VirgilPFSPrivateKey jarg3_);

    public final static native long new_VirgilPFSResponderPrivateInfo__SWIG_1(long jarg1, VirgilPFSPrivateKey jarg1_,
            long jarg2, VirgilPFSPrivateKey jarg2_);

    public final static native long VirgilPFSResponderPrivateInfo_getIdentityPrivateKey(long jarg1,
            VirgilPFSResponderPrivateInfo jarg1_);

    public final static native long VirgilPFSResponderPrivateInfo_getLongTermPrivateKey(long jarg1,
            VirgilPFSResponderPrivateInfo jarg1_);

    public final static native long VirgilPFSResponderPrivateInfo_getOneTimePrivateKey(long jarg1,
            VirgilPFSResponderPrivateInfo jarg1_);

    public final static native void delete_VirgilPFSResponderPrivateInfo(long jarg1);

    public final static native long new_VirgilPFSSession__SWIG_0();

    public final static native long new_VirgilPFSSession__SWIG_1(byte[] jarg1, byte[] jarg2, byte[] jarg3,
            byte[] jarg4);

    public final static native boolean VirgilPFSSession_isEmpty(long jarg1, VirgilPFSSession jarg1_);

    public final static native byte[] VirgilPFSSession_getIdentifier(long jarg1, VirgilPFSSession jarg1_);

    public final static native byte[] VirgilPFSSession_getEncryptionSecretKey(long jarg1, VirgilPFSSession jarg1_);

    public final static native byte[] VirgilPFSSession_getDecryptionSecretKey(long jarg1, VirgilPFSSession jarg1_);

    public final static native byte[] VirgilPFSSession_getAdditionalData(long jarg1, VirgilPFSSession jarg1_);

    public final static native void delete_VirgilPFSSession(long jarg1);

    public final static native long new_VirgilPFS();

    public final static native long VirgilPFS_startInitiatorSession__SWIG_0(long jarg1, VirgilPFS jarg1_, long jarg2,
            VirgilPFSInitiatorPrivateInfo jarg2_, long jarg3, VirgilPFSResponderPublicInfo jarg3_, byte[] jarg4);

    public final static native long VirgilPFS_startInitiatorSession__SWIG_1(long jarg1, VirgilPFS jarg1_, long jarg2,
            VirgilPFSInitiatorPrivateInfo jarg2_, long jarg3, VirgilPFSResponderPublicInfo jarg3_);

    public final static native long VirgilPFS_startResponderSession__SWIG_0(long jarg1, VirgilPFS jarg1_, long jarg2,
            VirgilPFSResponderPrivateInfo jarg2_, long jarg3, VirgilPFSInitiatorPublicInfo jarg3_, byte[] jarg4);

    public final static native long VirgilPFS_startResponderSession__SWIG_1(long jarg1, VirgilPFS jarg1_, long jarg2,
            VirgilPFSResponderPrivateInfo jarg2_, long jarg3, VirgilPFSInitiatorPublicInfo jarg3_);

    public final static native long VirgilPFS_encrypt(long jarg1, VirgilPFS jarg1_, byte[] jarg2);

    public final static native byte[] VirgilPFS_decrypt(long jarg1, VirgilPFS jarg1_, long jarg2,
            VirgilPFSEncryptedMessage jarg2_);

    public final static native long VirgilPFS_getSession(long jarg1, VirgilPFS jarg1_);

    public final static native void VirgilPFS_setSession(long jarg1, VirgilPFS jarg1_, long jarg2,
            VirgilPFSSession jarg2_);

    public final static native void delete_VirgilPFS(long jarg1);

    public final static native long VirgilCMSKeyTransRecipient_SWIGUpcast(long jarg1);

    public final static native long VirgilCMSPasswordRecipient_SWIGUpcast(long jarg1);

    public final static native long VirgilCMSEncryptedContent_SWIGUpcast(long jarg1);

    public final static native long VirgilCMSEnvelopedData_SWIGUpcast(long jarg1);

    public final static native long VirgilCMSContent_SWIGUpcast(long jarg1);

    public final static native long VirgilCMSContentInfo_SWIGUpcast(long jarg1);

    public final static native long VirgilHash_SWIGUpcast(long jarg1);

    public final static native long VirgilKDF_SWIGUpcast(long jarg1);

    public final static native long VirgilSymmetricCipher_SWIGUpcast(long jarg1);

    public final static native long VirgilAsymmetricCipher_SWIGUpcast(long jarg1);

    public final static native long VirgilPBE_SWIGUpcast(long jarg1);

    public final static native long VirgilPBKDF_SWIGUpcast(long jarg1);

    public final static native long VirgilCustomParams_SWIGUpcast(long jarg1);

    public final static native long VirgilCipher_SWIGUpcast(long jarg1);

    public final static native long VirgilChunkCipher_SWIGUpcast(long jarg1);

    public final static native long VirgilSigner_SWIGUpcast(long jarg1);

    public final static native long VirgilStreamSigner_SWIGUpcast(long jarg1);

    public final static native long VirgilStreamCipher_SWIGUpcast(long jarg1);

    public static boolean SwigDirector_VirgilDataSource_hasData(VirgilDataSource jself) throws java.io.IOException {
        return jself.hasData();
    }

    public static byte[] SwigDirector_VirgilDataSource_read(VirgilDataSource jself) throws java.io.IOException {
        return jself.read();
    }

    public static boolean SwigDirector_VirgilDataSink_isGood(VirgilDataSink jself) throws java.io.IOException {
        return jself.isGood();
    }

    public static void SwigDirector_VirgilDataSink_write(VirgilDataSink jself, byte[] data) throws java.io.IOException {
        jself.write(data);
    }

}
