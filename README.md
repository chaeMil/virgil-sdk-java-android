# Virgil Security Java/Android SDK

[Installation](#installation) | [Encryption Example](#encryption-example) | [Initialization](#initialization) | [Documentation](#documentation) | [Support](#support)

[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communication, securely store data, provide passwordless login, and ensure data integrity.

For a full overview head over to our Java/Android [Get Started][_getstarted] guides.

## Installation

The Virgil SDK is provided as set of packages named *com.virgilsecurity.sdk*. Packages are distributed via Maven repository.

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

## Documentation

Virgil Security has a powerful set of APIs, and the documentation is there to get you started today.

* [Get Started][_getstarted_root] documentation
  * [Initialize the SDK][_initialize_root]
  * [Encrypted storage][_getstarted_storage]
  * [Encrypted communication][_getstarted_encryption]
  * [Data integrity][_getstarted_data_integrity]
  * [Passwordless login][_getstarted_passwordless_login]
* [Guides][_guides]
  * [Virgil Cards][_guide_virgil_cards]
  * [Virgil Keys][_guide_virgil_keys]

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support

Our developer support team is here to help you. You can find us on [Twitter](https://twitter.com/virgilsecurity) and [email](support).

[support]: mailto:support@virgilsecurity.com
[_getstarted_root]: https://virgilsecurity.com/docs/sdk/java-android/
[_getstarted]: https://virgilsecurity.com/docs/sdk/java-android/getting-started
[_getstarted_encryption]: https://virgilsecurity.com/docs/use-cases/encrypted-communication
[_getstarted_storage]: https://virgilsecurity.com/docs/use-cases/secure-data-at-rest
[_getstarted_data_integrity]: https://virgilsecurity.com/docs/use-cases/data-verification
[_getstarted_passwordless_login]: https://virgilsecurity.com/docs/use-cases/passwordless-authentication
[_guides]: https://virgilsecurity.com/docs/sdk/java-android/features
[_guide_initialization]: https://virgilsecurity.com/docs/sdk/java-android/getting-started#initializing
[_guide_virgil_cards]: https://virgilsecurity.com/docs/sdk/java-android/features#virgil-cards
[_guide_virgil_keys]: https://virgilsecurity.com/docs/sdk/java-android/features#virgil-keys
[_guide_encryption]: https://virgilsecurity.com/docs/sdk/java-android/features#encryption
[_initialize_root]: https://virgilsecurity.com/docs/sdk/java-android/programming-guide#initializing
