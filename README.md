# Iron ECDSA SD 2023 Signature Suite

An implementation of the [W3C ECDSA SD 2023](https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-sd-2023) in Java.


## Installation

### Maven
Java 17+

```xml
<dependency>
    <groupId>com.apicatalog</groupId>
    <artifactId>iron-ecdsa-sd-2023</artifactId>
    <version>0.14.0</version>
</dependency>

<dependency>
    <groupId>com.apicatalog</groupId>
    <artifactId>iron-verifiable-credentials</artifactId>
    <version>0.14.0</version>
</dependency>
```

### Gradle

Android 12+ (API Level 31+)

```gradle
compile group: 'com.apicatalog', name: 'iron-ecdsa-sd-2023-jre8', version: '0.14.0'
compile group: 'com.apicatalog', name: 'iron-verifiable-credentials-jre8', version: '0.14.0'
```

## Documentation

[![javadoc](https://javadoc.io/badge2/com.apicatalog/iron-ecdsa-sd-2023/javadoc.svg)](https://javadoc.io/doc/com.apicatalog/iron-ecdsa-sd-2023)

## Contributing

All PR's welcome!

### Building

Fork and clone the project repository.

#### Java 17
```bash
> cd iron-ecdsa-sd-2023
> mvn clean package
```

#### Java 8
```bash
> cd iron-ecdsa-sd-2023
> mvn -f pom_jre8.xml clean package
```

## Resources
* [W3C ECDSA SD 2023](https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-sd-2023)
* [Iron Verifiable Credentials](https://github.com/filip26/iron-verifiable-credentials)

## Sponsors

<a href="https://github.com/digitalbazaar">
  <img src="https://avatars.githubusercontent.com/u/167436?s=200&v=4" width="40" />
</a> 

## Commercial Support
Commercial support is available at filip26@gmail.com

