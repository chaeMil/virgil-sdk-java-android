# Virgil Security SDK and Crypto stack Java/Android

[![Build Status](https://api.travis-ci.org/VirgilSecurity/virgil-sdk-java-android.svg?branch=master)](https://travis-ci.org/VirgilSecurity/virgil-sdk-java-android)
[![Maven](https://img.shields.io/maven-central/v/com.virgilsecurity.sdk/sdk-android.svg)](https://img.shields.io/maven-central/v/com.virgilsecurity.sdk/sdk-android.svg)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#installation) | [SDK Features](#sdk-features) | [Library purposes](#library-purposes) | [Installation](#installation) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)


## Introduction

[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communication, securely store data, provide passwordless login, and ensure data integrity.

The Virgil SDK allows developers to get up and running with Virgil API quickly and add full end-to-end security to their existing digital solutions to become HIPAA and GDPR compliant and more.

## SDK Features
- communicate with [Virgil Cards Service][_cards_service]
- manage users' Public Keys
- store private keys in secure local storage
- use Virgil [Crypto library][_virgil_crypto]
- use your own Crypto

## Crypto Library purposes
* Asymmetric Key Generation
* Encryption/Decryption of data and streams
* Generation/Verification of digital signatures
* PFS (Perfect Forward Secrecy)

## Installation

The Virgil SDK is provided as set of packages named *com.virgilsecurity.sdk*. Packages are distributed via Maven repository.  Also in this guide, you find one more package - Virgil Crypto Library that is used by the SDK to perform cryptographic operations.

### Target

* Java 7+.
* Android API 16+.

### Prerequisites

* Java Development Kit (JDK) 7+
* Maven 3+

### Installing the package

You can easily add SDK dependency to your project, just follow the examples below:

#### Maven

Use this packages for Java projects.

```
<dependencies>
    <dependency>
        <groupId>com.virgilsecurity.sdk</groupId>
        <artifactId>crypto</artifactId>
        <version>5.0.0</version>
    </dependency>
    <dependency>
        <groupId>com.virgilsecurity.sdk</groupId>
        <artifactId>sdk</artifactId>
        <version>5.0.0</version>
    </dependency>
</dependencies>
```

#### Gradle

Use this packages for Android projects.

```
dependencies {
    compile 'com.virgilsecurity.sdk:crypto-android:5.0.0@aar'
    compile 'com.virgilsecurity.sdk:sdk:5.0.0'
}
```


## Usage Examples

#### Generate and publish user's Cards with Public Keys inside on Cards Service
Use the following lines of code to create and publish a user's Card with Public Key inside on Virgil Cards Service:

```java
VirgilCrypto crypto = new VirgilCrypto();

// generate a key pair
VirgilKeyPair keyPair = crypto.generateKeys();

// save a private key into key storage
privateKeyStorage.store(keyPair.getPrivateKey(), "Alice", null);

// publish user's on the Cards Service
try {
    Card card = cardManager.publishCard(keyPair.getPrivateKey(), keyPair.getPublicKey(), "Alice");
    // Card is created
} catch (Exception e) {
    // Error occured
}
```

#### Sign then encrypt data

Virgil SDK lets you use a user's Private key and his or her Cards to sign, then encrypt any kind of data.

In the following example, we load a Private Key from a customized Key Storage and get recipient's Card from the Virgil Cards Services. Recipient's Card contains a Public Key on which we will encrypt the data and verify a signature.

```java
VirgilCrypto crypto = new VirgilCrypto();

// prepare a message
String messageToEncrypt = "Hello, Bob!";
byte[] dataToEncrypt = ConvertionUtils.toBytes(messageToEncrypt);

// prepare a user's private key
Tuple<PrivateKey, Map<String, String>> alicePrivateKeyEntry =
        privateKeyStorage.load("Alice");
VirgilPrivateKey alicePrivateKey =
        (VirgilPrivateKey) alicePrivateKeyEntry.getLeft();

// using cardManager search for user's cards on Cards Service
try {
    List<Card> cards = cardManager.searchCards("Bob");
    // Cards are obtained
    List<VirgilPublicKey> bobRelevantCardsPublicKeys = new ArrayList<>();
    for (Card card : cards) {
        if (!card.isOutdated()) {
            bobRelevantCardsPublicKeys.add(
                    (VirgilPublicKey) card.getPublicKey());
        }
    }
    // sign a message with a private key then encrypt on a public key
    byte[] encryptedData = crypto.signThenEncrypt(dataToEncrypt,
            alicePrivateKey, bobRelevantCardsPublicKeys);
} catch (CryptoException | VirgilServiceException e) {
    // Error occured
}
```

#### Decrypt then verify data
Once the Users receive the signed and encrypted message, they can decrypt it with their own Private Key and verify signature with a Sender's Card:

```java
VirgilCrypto crypto = new VirgilCrypto();

// prepare a user's private key
Tuple<PrivateKey, Map<String, String>> bobPrivateKeyEntry =
        privateKeyStorage.load("Bob");
VirgilPrivateKey bobPrivateKey =
        (VirgilPrivateKey) bobPrivateKeyEntry.getLeft();

try {
    // using cardManager search for user's cards on Cards Service
    List<Card> cards = cardManager.searchCards("Alice");
    // Cards are obtained
    List<VirgilPublicKey> aliceRelevantCardsPublicKeys = new ArrayList<>();
    for (Card card : cards) {
        if (!card.isOutdated()) {
            aliceRelevantCardsPublicKeys.add(
                    (VirgilPublicKey) card.getPublicKey());
        }
    }

    // decrypt with a private key and verify using a public key
    byte[] decryptedData = crypto.decryptThenVerify(encryptedData,
            bobPrivateKey, aliceRelevantCardsPublicKeys);
} catch (CryptoException | VirgilServiceException e) {
    // Error occured
}
```

## Docs
Virgil Security has a powerful set of APIs, and the documentation below can get you started today.

In order to use the Virgil SDK with your application, you will need to first configure your application. By default, the SDK will attempt to look for Virgil-specific settings in your application but you can change it during SDK configuration.

* [Configure the SDK][_configure_sdk] documentation
  * [Setup authentication][_setup_authentication] to make API calls to Virgil Services
  * [Setup Card Manager][_card_manager] to manage user's Public Keys
  * [Setup Card Verifier][_card_verifier] to verify signatures inside of user's Card
  * [Setup Key storage][_key_storage] to store Private Keys
  * [Setup your own Crypto library][_own_crypto] inside of the SDK
* [More usage examples][_more_examples]
  * [Create & publish a Card][_create_card] that has a Public Key on Virgil Cards Service
  * [Search user's Card by user's identity][_search_card]
  * [Get user's Card by its ID][_get_card]
  * [Use Card for crypto operations][_use_card]
* [Reference API][_reference_api]


## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://join.slack.com/t/VirgilSecurity/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).

[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-crypto
[_cards_service]: https://developer.virgilsecurity.com/docs/api-reference/card-service/v5
[_use_card]: https://developer.virgilsecurity.com/docs/java/how-to/public-key-management/use-card-for-crypto-operation
[_get_card]: https://developer.virgilsecurity.com/docs/java/how-to/public-key-management/get-card
[_search_card]: https://developer.virgilsecurity.com/docs/java/how-to/public-key-management/search-card
[_create_card]: https://developer.virgilsecurity.com/docs/java/how-to/public-key-management/create-card
[_own_crypto]: https://developer.virgilsecurity.com/docs/java/how-to/setup/setup-own-crypto-library
[_key_storage]: https://developer.virgilsecurity.com/docs/java/how-to/setup/setup-key-storage
[_card_verifier]: https://developer.virgilsecurity.com/docs/java/how-to/setup/setup-card-verifier
[_card_manager]: https://developer.virgilsecurity.com/docs/java/how-to/setup/setup-card-manager
[_setup_authentication]: https://developer.virgilsecurity.com/docs/java/how-to/setup/setup-authentication
[_reference_api]: https://developer.virgilsecurity.com/docs/api-reference
[_configure_sdk]: https://developer.virgilsecurity.com/docs/how-to#sdk-configuration
[_more_examples]: https://developer.virgilsecurity.com/docs/how-to#public-key-management
