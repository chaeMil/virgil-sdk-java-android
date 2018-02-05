
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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Date;

import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeysType;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.highlevel.AppCredentials;
import com.virgilsecurity.sdk.highlevel.EmailConfirmation;
import com.virgilsecurity.sdk.highlevel.IdentityValidationToken;
import com.virgilsecurity.sdk.highlevel.IdentityVerificationAttempt;
import com.virgilsecurity.sdk.highlevel.StringEncoding;
import com.virgilsecurity.sdk.highlevel.VirgilApi;
import com.virgilsecurity.sdk.highlevel.VirgilApiContext;
import com.virgilsecurity.sdk.highlevel.VirgilApiImpl;
import com.virgilsecurity.sdk.highlevel.VirgilBuffer;
import com.virgilsecurity.sdk.highlevel.VirgilCard;
import com.virgilsecurity.sdk.highlevel.VirgilCards;
import com.virgilsecurity.sdk.highlevel.VirgilKey;
import com.virgilsecurity.sdk.storage.PrivateKeyStorage;

/**
 * @author Andrii Iakovenko
 *
 */
public class HiLevelSample {

    private static final String ACCESS_TOKEN = "[YOUR_APP_ACCESS_TOKEN_HERE]";
    private static final String APP_ID = "[YOUR_APP_ID_HERE]";
    private static final String APP_KEY_PASSWORD = "[YOUR_APP_KEY_PASSWORD_HERE]";
    private static final String APP_KEY = "[YOUR_APP_KEY_HERE]";

    private static final String ALICE_EMAIL_IDENTITY = "alice@mailinator.com";

    private static final String ALICE_KEY_NAME = "ALICE";
    private static final String ALICE_KEY_PWD = "12345678";
    private static final String BOB_KEY_NAME = "BOB";
    private static final String BOB_KEY_PWD = "1234567890";

    private static String aliceIdentity;
    private static String bobIdentity;

    public static void main(String[] args) throws IOException, VirgilException {
        clear();
        globalCards();
        localCards();
        clear();
        encryption();
        authenticatedEncryption();
        signatures();

        System.out.println("Done");
    }

    private static void globalCards() throws IOException, VirgilException {
        /** Initialize high-level SDK with only application access token */
        VirgilApiContext ctx = new VirgilApiContext(ACCESS_TOKEN);
        ctx.setKeyStorage(/* keystorage you set for secure chat context */ new PrivateKeyStorage());
        VirgilApi virgil = new VirgilApiImpl(ctx);

        /** Register Global Virgil Card */
        VirgilKey aliceKey = virgil.getKeys().generate().save(ALICE_KEY_NAME, ALICE_KEY_PWD);

        // create alice's Card using her newly generated Key.
        VirgilCard aliceCard = virgil.getCards().createGlobal(ALICE_EMAIL_IDENTITY, aliceKey, GlobalCardIdentityType.EMAIL);
        String aliceCardId = aliceCard.getId();

        // initiate an getIdentity verification process.
        IdentityVerificationAttempt attempt = aliceCard.checkIdentity();

        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Enter confirmation code");
        String confirmationCode = br.readLine();

        // confirm a Card's getIdentity using confirmation code retrived on the email.
//        IdentityValidationToken token = attempt.confirm(new EmailConfirmation(confirmationCode));

        // publish a Card on the Virgil Security services.
//        virgil.getCards().publishGlobal(aliceCard, token);
        // aliceCard.publishAsGlobal(token);

        /** Revoke Global Virgil Card */
        // load alice's Key from secure storage provided by default.
        aliceKey = virgil.getKeys().load(ALICE_KEY_NAME, ALICE_KEY_PWD);

        // load alice's Card from Virgil Security services.
        aliceCard = virgil.getCards().get(aliceCardId);

        // initiate Card's getIdentity verification process.
        attempt = aliceCard.checkIdentity();

        System.out.println("Enter confirmation code");
        confirmationCode = br.readLine();

        // confirm Card's getIdentity using confirmation code and grub validation token.
//        token = attempt.confirm(new EmailConfirmation(confirmationCode));

        // revoke Virgil Card from Virgil Security services.
//        virgil.getCards().revokeGlobal(aliceCard, aliceKey, token);
    }

    private static void localCards() throws VirgilException {
        /** Register Local Virgil Card */
        // initialize Virgil SDK
        AppCredentials credentials = new AppCredentials();
        credentials.setAppId(APP_ID);
        credentials.setAppKey(VirgilBuffer.from(APP_KEY));
        credentials.setAppKeyPassword(APP_KEY_PASSWORD);

        VirgilApiContext context = new VirgilApiContext(ACCESS_TOKEN);
        context.setCredentials(credentials);

        VirgilApi virgil = new VirgilApiImpl(context);

        // generate and save alice's Key
        VirgilKey aliceKey = virgil.getKeys().generate().save(ALICE_KEY_NAME, ALICE_KEY_PWD);

        // create alice's Card using her Key
        VirgilCard aliceCard = virgil.getCards().create(aliceIdentity, aliceKey);

        // export alice's Card to string
        String exportedAliceCard = aliceCard.export();

        /** Publish a Virgil Card */
        // import alice's Card from its string representation.
        aliceCard = virgil.getCards().importCard(exportedAliceCard);
        String aliceCardId = aliceCard.getId();

        // verifySignature alice's Card information before publishing it on the Virgil services.

        // aliceCard.getIdentity()
        // aliceCard.getIdentityType()
        // aliceCard.getCustomFields()

        // publish alice's Card on Virgil Services
        virgil.getCards().publish(aliceCard);
        // aliceCard.publish();

        /** Revoke Local Virgil Card */
        // get alice's Card by ID
        aliceCard = virgil.getCards().get(aliceCardId);

        // revoke alice's Card from Virgil Security services.
        virgil.getCards().revoke(aliceCard);
    }

    public static void encryption() throws VirgilException {
        /** Initialization */
        // initialize Virgil SDK
        AppCredentials credentials = new AppCredentials();
        credentials.setAppId(APP_ID);
        credentials.setAppKey(VirgilBuffer.from(APP_KEY));
        credentials.setAppKeyPassword(APP_KEY_PASSWORD);

        VirgilApiContext context = new VirgilApiContext(ACCESS_TOKEN);
        context.setCredentials(credentials);

        VirgilApi virgil = new VirgilApiImpl(context);

        // generate and save Alice's Key
        VirgilKey aliceKey = virgil.getKeys().generate().save(ALICE_KEY_NAME, ALICE_KEY_PWD);

        // create and publish Alice's Card using her Key
        VirgilCard aliceCard = virgil.getCards().create(aliceIdentity, aliceKey).publish();

        /** Encrypt data */
        // search for alice's and bob's Cards
        VirgilCards aliceCards = virgil.getCards().find(aliceIdentity);

        String message = "Hello Guys, let's get outta here.";

        // encrypt message for multiple recipients
        VirgilBuffer encryptedMessage = aliceCards.encrypt(message);

        String transferData = encryptedMessage.toString(StringEncoding.Base64);
        // var transferData = cipherData.ToString(StringEncoding.Hex);
        // var transferData = cipherData.ToBytes();

        /** Decrypt data */
        // load alice's Key from secure storage provided by default.
        aliceKey = virgil.getKeys().load(ALICE_KEY_NAME, ALICE_KEY_PWD);

        // get buffer from base64 encoded string
        VirgilBuffer encryptedData = VirgilBuffer.from(transferData, StringEncoding.Base64);

        // decrypt message using alice's Private key.
        VirgilBuffer originalData = aliceKey.decrypt(encryptedData);

        String originalMessage = originalData.toString();
        // var originalMessage = originalData.ToString(StringEncoding.Base64);
        // var originalMessage = originalData.ToString(StringEncoding.Hex);
        // var originalMessage = originalData.ToBytes(); }
    }

    public static void authenticatedEncryption() throws VirgilException {
        /** Initialization */
        // initialize Virgil SDK
        AppCredentials credentials = new AppCredentials();
        credentials.setAppId(APP_ID);
        credentials.setAppKey(VirgilBuffer.from(APP_KEY));
        credentials.setAppKeyPassword(APP_KEY_PASSWORD);

        VirgilApiContext context = new VirgilApiContext(ACCESS_TOKEN);
        context.setCredentials(credentials);

        VirgilApi virgil = new VirgilApiImpl(context);

        /** Sign then Encrypt Data */
        // load alice's key pair from secure storage defined by default
        VirgilKey aliceKey = virgil.getKeys().load(ALICE_KEY_NAME, ALICE_KEY_PWD);

        VirgilKey bobKey = virgil.getKeys().generate().save(BOB_KEY_NAME, BOB_KEY_PWD);
        virgil.getCards().create(bobIdentity, bobKey).publish();

        // search for bob's and chris' Cards
        VirgilCards recipients = virgil.getCards().find(bobIdentity, "chris");

        String message = "Hello Guys, let's get outta here.";

        // encrypt and generateStreamSignature message for multiple recipients
        VirgilBuffer cipherData = aliceKey.signThenEncrypt(message, recipients);

        String transferData = cipherData.toString(StringEncoding.Base64);

        /** Decrypt then Verify Data */
        // load bob's Key from secure storage defined by default
        bobKey = virgil.getKeys().load(BOB_KEY_NAME, BOB_KEY_PWD);

        // search for alice's Card
        VirgilCards aliceCards = virgil.getCards().find(aliceIdentity);
        VirgilCard aliceCard = aliceCards.get(0);

        // get buffer from base64 encoded string
        VirgilBuffer encryptedData = VirgilBuffer.from(transferData, StringEncoding.Base64);

        // decrypt cipher message bob's key pair and verifySignature it using alice's Card
        VirgilBuffer originalData = bobKey.decryptThenVerify(encryptedData, aliceCard);

        String originalMessage = originalData.toString();
    }

    private static void signatures() throws VirgilException {
        /** Initialization */
        // initialize Virgil SDK high-level instance
        VirgilApi virgil = new VirgilApiImpl(ACCESS_TOKEN);

        /** Generate Digital Signature */
        // load alice's Key from protected storage
        VirgilKey aliceKey = virgil.getKeys().load(ALICE_KEY_NAME, ALICE_KEY_PWD);

        String message = "Hey Bob, hope you are doing well.";

        // generate signature of message using alice's key pair
        VirgilBuffer signature = aliceKey.sign(message);
        String transferData = signature.toString(StringEncoding.Base64);

        /** Validate Digital Signature */
        // search for alice's Card
        VirgilCards aliceCards = virgil.getCards().find(aliceIdentity);
        VirgilCard aliceCard = aliceCards.get(0);

        if (!aliceCard.verify(message, signature)) {
            System.out.println("Signature is not valid.");
        }
    }

    public void generateSpecifiedKeyType() {
        // initialize the Crypto with specified key pair type.
        Crypto crypto = new VirgilCrypto(KeysType.EC_BP512R1);

        // initialize a High Level API class with custom Crypto instance.
        VirgilApiContext context = new VirgilApiContext();
        context.setCrypto(crypto);

        VirgilApi virgil = new VirgilApiImpl(context);

        // generate a new private key
        VirgilKey aliceKey = virgil.getKeys().generate();
    }

    public void exportImportKey() throws VirgilException {
        // initialize a High Level API class
        VirgilApi virgil = new VirgilApiImpl();

        // generate a new private key
        VirgilKey aliceKey = virgil.getKeys().generate();

        // export the Virgil Key to Base64 encoded string
        String exportedKey = aliceKey.export("[OPTIONAL_KEY_PASSWORD]").toString(StringEncoding.Base64);

        VirgilBuffer keyBuffer = VirgilBuffer.from(exportedKey, StringEncoding.Base64);

        // import the Virgil Key from Base64 encoded string
        aliceKey = virgil.getKeys().importKey(keyBuffer, "[OPTIONAL_KEY_PASSWORD]");
    }

    private static void clear() {
        try {
            new VirgilApiImpl().getKeys().destroy(ALICE_KEY_NAME);
        } catch (Exception e) {
        }
        try {
            new VirgilApiImpl().getKeys().destroy(BOB_KEY_NAME);
        } catch (Exception e) {
        }
        aliceIdentity = "alice" + new Date().getTime();
        bobIdentity = "bob" + new Date().getTime();
    }

}
