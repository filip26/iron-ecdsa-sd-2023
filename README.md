# Iron ECDSA SD 2023 Signature Suite

An implementation of the [W3C ECDSA SD 2023](https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-sd-2023) in Java.

[![Java 17 CI](https://github.com/filip26/iron-ecdsa-sd-2023/actions/workflows/java17-build.yml/badge.svg)](https://github.com/filip26/iron-ecdsa-sd-2023/actions/workflows/java17-build.yml)
[![Android (Java 8) CI](https://github.com/filip26/iron-ecdsa-sd-2023/actions/workflows/java8-build.yml/badge.svg)](https://github.com/filip26/iron-ecdsa-sd-2023/actions/workflows/java8-build.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/aec38cb6132a4d3386181273b620c9c7)](https://app.codacy.com/gh/filip26/iron-ecdsa-sd-2023/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/aec38cb6132a4d3386181273b620c9c7)](https://app.codacy.com/gh/filip26/iron-ecdsa-sd-2023/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_coverage)
[![Maven Central](https://img.shields.io/maven-central/v/com.apicatalog/iron-ecdsa-sd-2023.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:com.apicatalog%20AND%20a:iron-ecdsa-sd-2023)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Features
* [W3C ECDSA SD Signature 2023](https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-sd-2023)
  * Verifier, Issuer, Holder
  * Key pair generator
  * P-256 (secp256r1), P-384 (secp384r1) [planned]
* [VC HTTP API & Service](https://github.com/filip26/iron-vc-api)

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
implementation("com.apicatalog:iron-ecdsa-sd-2023-jre8:0.14.0")
implementation("com.apicatalog:iron-verifiable-credentials-jre8:0.14.0")
```


### Verifier

```javascript
// create a new verifier instance
static Verifier VERIFIER = Verifier.with(new ECDSASelective2023())
    // options
    .loader(...)
    .statusValidator(...)
    .subjectValidator(...);

try {
  // verify the given input proof(s)
  var verifiable = VERIFIER.verify(credential|presentation);
  
  // or with runtime parameters e.g. domain, challenge, etc.
  var verifiable = VERIFIER.verify(credential|presentation, parameters);
  
  // get verified details
  verifiable.subject()
  verifiable.id()
  verifiable.type()
  // ...
  
} catch (VerificationError | DocumentError e) {
  ...
}

```

### Issuer

```javascript

// create a signature suite static instance
static SignatureSuite SUITE = new ECDSASelective2023();

// create a new issuer instance
Issuer ISSUER = SUITE.createIssuer(keyPairProvider)
  // options
  .loader(...);
    
try {
  // create a new proof draft using P-256
  var draft = SUITE.createP256Draft(verificationMethod, purpose);
  // mandatory pointers
  draft.selectors(...); 
  
  // keys
  draft.proofKeys(proofKeys);
  draft.hmacKey(hmacKey);
  // or generate the keys
  draft.useGeneratedHmacKey(32);
  draft.useGeneratedProofKeys();
  
  // custom options
  draft.created(...);
  draft.domain(...);
  ...

  // issue a new verifiable, i.e. sign the input and add a new proof
  var verifiable = ISSUER.sign(credential|presentation, draft).compacted();
  
} catch (SigningError | DocumentError e) {
  ...
}
```

### Holder

```javascript

// create a signature suite static instance
static SignatureSuite SUITE = new ECDSASelective2023();

// create a new issuer instance
Holder HOLDER = Holder.with(SUITE);
  // options
  .loader(...);
    
try {

  // derive a new verifiable disclosing only selected claims
  var verifiable = HOLDER.derive(credential|presentation, selectors).compacted();
  
} catch (SigningError | DocumentError e) {
  ...
}
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

