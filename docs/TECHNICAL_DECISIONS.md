# Technical decisions

## Overview

```
Client                 Authorization server (9000)         Resource server (8080)
  | POST /oauth2/token          |                                   |
  | subject=alice               |                                   |
  |---------------------------->| signs with the active key (kid)   |
  |<---- JWT RS256 -------------|                                   |
  | GET /api/hello, Bearer JWT                                      |
  |---------------------------------------------------------------->|
  |                             |<-- GET jwks.json (unknown kid) ---|
  |                             |--- public keys ------------------>| verifies signature,
  |<------------------------------------------- 200 Hello, alice! --| iss, aud, exp
```

## Decisions

### Two applications in a multi-module Maven project

The servers are deployed separately and share only standard contracts (JWT, JWKS), not code. There
is deliberately no common module: the resource server knows the authorization server only through
its configured URLs. The multi-module setup keeps a single build for a small project.

### Asymmetric RS256 signing rather than HS256

With HS256, any service able to verify a token could also forge one, since the secret is shared.
With RS256, only the authorization server holds the private key. The resource server accepts only
RS256, which rules out `alg: none` and RS256/HS256 confusion; both attacks are covered by tests.
ES256 would be a good candidate (shorter keys and signatures), RS256 remaining the most widely
interoperable choice.

### Key distribution through JWKS, rotation through `kid`

Each token identifies its key in the `kid` header. The resource server caches the JWKS and reloads
it when it encounters an unknown `kid`. This is what meets the requirement of the brief: a token
signed by a new key is accepted with no restart or reconfiguration.

Rotation on the issuer side is reduced to the minimum, behind the `demo` profile:
`POST /demo/keys/rotate` activates a new key and keeps the previous one in the JWKS, so that tokens
in circulation stay valid. The key ring is limited to two keys. There is no scheduling or gradual
retirement, as per the brief.

### Spring Security without Spring Authorization Server

Spring Authorization Server would be the right choice in production. It implements the standard
flows, whereas the brief asks for a flow that is not one of them (see below) and aims to show the
mechanisms. Issuance therefore relies on `JwtEncoder` and Nimbus, in a few readable classes.

On the resource side, by contrast, everything is delegated to the standard support:
`oauth2ResourceServer().jwt()` and the Spring Boot properties. The safest security code is the code
you don't write.

### Accepted deviations from OAuth 2.0

`POST /oauth2/token` with `subject` follows the RFC 6749 response and error format, but **is not an
OAuth 2.0 grant**. The brief requires it, and it has an obvious flaw outside a demo: **anyone can
get a token for any subject**, because neither the client nor the user is authenticated. Going to
production would require `client_credentials` (service to service) or `authorization_code` with PKCE (user).

### Validation on the resource server

| Check                                                              | Attack or error prevented                                              |
|--------------------------------------------------------------------|------------------------------------------------------------------------|
| Signature and algorithm                                            | Forged token, `alg: none`, algorithm confusion                         |
| `iss`                                                              | Token from another issuer                                              |
| `aud`                                                              | Token meant for another API and replayed here                          |
| `exp` (60 s tolerance by default)                                  | Expired token                                                          |
| `exp`, `iat` and `sub` required                                    | Token with no expiry or no subject, which Spring Security would accept |
| `iat` not in the future (60 s tolerance), lifetime of 24 h at most | Token with an excessive lifetime                                       |

### Short lifetime

Without introspection, a JWT cannot be revoked before it expires. The 15-minute lifetime limits this
window. `jti` is present to allow a future revocation list.

### Secure by default

- Authorization server denies by default: only the listed routes are reachable.
- Stateless API: no session, and CSRF disabled since no cookie authenticates requests.
- `Cache-Control: no-store` on token responses.
- JWKS serialized from a public view, a test verifies the absence of private material.
- Rotation endpoint absent without the `demo` profile.
- Token parameters accepted in the body only and without repetition (RFC 6749, section 3.2).
- URLs published in the RFC 9728 metadata and in `WWW-Authenticate` come from the configuration,
  never from the `Host` header.

## Code architecture

Organized by feature rather than by technical layer:

```
authorization-server        resource-server
├── token    issuance       ├── hello    protected endpoint
├── jwks     publication    └── config   security
├── key      key ring
├── demo     simulated rotation
└── config   security, encoder, properties
```

The `SigningKeyRing` interface isolates key management: replacing in-memory storage with a KMS or
Vault touches neither issuance nor publication. The lifetime, issuer and audience are externalized
and validated at startup. `Clock` is injected to test dates without waiting.

## Test strategy

| Level                             | Scope                                                                                                                                                      |
|-----------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Unit                              | Key ring (rotation, no exposed private key), token claims and signature                                                                                    |
| MockMvc integration               | HTTP contract and security rules of the authorization server                                                                                               |
| Integration with a real HTTP JWKS | Resource server rejections and rotation, through a small local HTTP server rather than a mocked `JwtDecoder`, to exercise the real key loading and caching |
| Postman end-to-end                | Both real servers, full journey                                                                                                                            |

## Known limitations

In priority order for going to production:

1. **Unauthenticated token endpoint**: see "Accepted deviations".
2. **No limit on JWKS reloads.** Measured on this project: 20 requests with unknown `kid`s cause 20
   JWKS calls. An attacker with no valid token can thus generate traffic to the authorization
   server. Fix: Nimbus `JWKSourceBuilder` with rate limiting, choosing the interval carefully, as an
   interval that is too long delays the acceptance of a genuine new key. Not implemented here, to
   keep the standard Spring Boot decoder.
3. **In-memory keys**: lost on restart and incompatible with multiple instances. A KMS or a vault
   would be needed.
4. **HTTP locally**: TLS is essential outside a development workstation, for tokens as well as for
   the JWKS, whose integrity underpins all of the resource server's trust.
5. **No scopes**: any valid token can access HelloWorld, as the brief provides for only one resource.
6. **Key retirement**: a retired key remains accepted by the resource server as long as it stays in
   its JWKS cache. A real rotation must take this into account.

## Use of AI tools

This project was developed with Claude Code from the brief: structure, code, tests, collection and
documentation. The results were checked by execution, with the Maven build and a Postman run against
the real servers, rather than by review alone. The measurement of JWKS reloads (limitation no. 2) is
an example: the behavior was verified by a test rather than assumed.
