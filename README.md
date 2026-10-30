# OAuth 2.0 Challenge

Two independent Spring Boot APIs:

| Service                | Port | Role                                             |
|------------------------|------|--------------------------------------------------|
| `authorization-server` | 9000 | Issues signed JWTs and publishes the public keys |
| `resource-server`      | 8080 | Exposes a JWT-protected HelloWorld endpoint      |

The technical decisions are explained in [docs/TECHNICAL_DECISIONS.md](docs/TECHNICAL_DECISIONS.md).

## Prerequisites

- JDK 25 (`java -version`). Maven is not required, the `./mvnw` wrapper is provided.
- Ports 8080 and 9000 free.
- Postman, or Postman CLI, for the demo.

## Running the project

In two terminals, from the project root:

```bash
# Terminal 1: the demo profile enables the rotation simulation endpoint
./mvnw -pl authorization-server spring-boot:run -Dspring-boot.run.profiles=demo

# Terminal 2
./mvnw -pl resource-server spring-boot:run
```

The startup order does not matter. On Windows, use `mvnw.cmd`.

## Testing

### Automated tests

```bash
./mvnw verify
```

### Postman demo

The collection is stored in the Postman v3 YAML format, in
`postman/collections/Challenge OAuth 2.0`. In the Postman app, open the project root in Local Mode,
then run the collection in order with the Collection Runner. From the command line:

```bash
postman collection run "postman/collections/Challenge OAuth 2.0"
```

The collection runs the happy path, the rejection cases, then the key rotation. It can be replayed
without restarting the servers.

### With curl

```bash
TOKEN=$(curl -s -X POST localhost:9000/oauth2/token -d subject=alice | sed -E 's/.*"access_token":"([^"]+)".*/\1/')
curl -i localhost:8080/api/hello -H "Authorization: Bearer $TOKEN"   # 200

curl -X POST localhost:9000/demo/keys/rotate                         # new active key
TOKEN2=$(curl -s -X POST localhost:9000/oauth2/token -d subject=alice | sed -E 's/.*"access_token":"([^"]+)".*/\1/')
curl -i localhost:8080/api/hello -H "Authorization: Bearer $TOKEN2"  # 200, no restart
```

## Endpoints

| Method | URL                                          | Description                                                        |
|--------|----------------------------------------------|--------------------------------------------------------------------|
| `POST` | `:9000/oauth2/token`                         | Form `subject=<subject>` in the body, sent once, returns the token |
| `GET`  | `:9000/.well-known/jwks.json`                | Public keys                                                        |
| `POST` | `:9000/demo/keys/rotate`                     | Simulates a rotation (`demo` profile only, 404 otherwise)          |
| `GET`  | `:8080/api/hello`                            | Protected, `Authorization: Bearer <token>` header                  |
| `GET`  | `:8080/.well-known/oauth-protected-resource` | RFC 9728 metadata                                                  |

## Configuration

Optional environment variables:

| Variable              | Default                                          | Service       |
|-----------------------|--------------------------------------------------|---------------|
| `TOKEN_ISSUER`        | `http://localhost:9000`                          | both          |
| `TOKEN_AUDIENCE`      | `hello-api` (several values separated by commas) | both          |
| `TOKEN_TIME_TO_LIVE`  | `15m` (from `1s` to `24h`)                       | authorization |
| `JWK_SET_URI`         | `http://localhost:9000/.well-known/jwks.json`    | resource      |
| `RESOURCE_SERVER_URL` | `http://localhost:8080`                          | resource      |

The authorization server refuses to start if `TOKEN_ISSUER`, `TOKEN_AUDIENCE` or
`TOKEN_TIME_TO_LIVE` is invalid.

## Troubleshooting

- **401 after restarting the authorization server**: expected, the keys are kept in memory.
  Request a new token.
- **404 on the rotation endpoint**: the authorization server was not started with the `demo` profile.
- **Compilation error "release version 25 not supported"**: `JAVA_HOME` points to an older JDK.
