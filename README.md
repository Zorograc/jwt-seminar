# JWT Security Research Lab

A Docker-based research project exploring common JSON Web Token (JWT) vulnerabilities and testing how different JWT libraries handle potentially malicious tokens.

The project was developed as part of a university seminar on authentication security. It provides a controlled environment for experimenting with JWT attacks across four different programming languages and implementations.

## Overview

The lab consists of four independent web applications, each using a different JWT library. All applications expose the same basic endpoints, allowing security testing across different implementations under similar conditions.

| Application | Language / Framework | JWT Library | Version | Port |
|---|---|---|---|---|
| PyJWT | Python / Flask | PyJWT | 2.8.0 | 5000 |
| jsonwebtoken | Node.js / Express | jsonwebtoken | 9.0.0 | 3000 |
| php-jwt | PHP | firebase/php-jwt | 6.10.0 | 8080 |
| jjwt | Java / Spring Boot | JJWT | 0.12.5 | 8081 |

### Endpoints

Each application exposes three endpoints:

- `/login` – Authenticates a user and issues a JWT.
- `/admin` – Protected endpoint requiring appropriate authorization.
- `/verify` – Validates a submitted JWT.

## Attack Scenarios

The project explores several common JWT attack techniques.

### 1. Algorithm Confusion – `alg: none`

JWT tokens specify their signing algorithm in the header. The `none` algorithm represents an unsigned token.

An attacker may attempt to modify a token's header to use `alg: none` and remove its signature, potentially bypassing signature verification in improperly configured implementations.

**Objective:** Test whether the applications correctly reject unsigned tokens and enforce signature verification.

**Observations:** All four tested modern implementations rejected the unsigned-token attack in the tested configurations.

### 2. Weak Secret Brute-Forcing

HMAC-signed JWTs rely on a shared secret to generate and verify signatures.

If an application uses a weak or predictable secret, an attacker who obtains a token can attempt an offline dictionary attack to recover the signing secret.

Once recovered, the attacker can generate valid tokens containing arbitrary claims.

**Objective:** Demonstrate the risks of weak JWT signing secrets and test the feasibility of recovering them using dictionary-based attacks.

**Tools:** [jwt_tool](https://github.com/ticarpi/jwt_tool)

**Security implications:** Use sufficiently long, cryptographically random secrets and rotate compromised signing keys. Rate limiting alone does not prevent offline JWT secret cracking.

### 3. JWT `kid` Header Manipulation

The `kid` (Key ID) header identifies the key used to verify a JWT signature.

If an application uses the value of `kid` insecurely when loading a signing key, an attacker may attempt path traversal or other forms of key-selection manipulation.

**Objective:** Investigate how JWT implementations and application-level key handling respond to manipulated `kid` headers.

### 4. RS256 to HS256 Key Confusion

JWT supports different signing algorithms, including:

- RS256 – Asymmetric RSA signature algorithm.
- HS256 – Symmetric HMAC signature algorithm.

An incorrectly implemented verifier may trust the algorithm specified in the token header and confuse the public RSA key with an HMAC secret.

This can potentially allow an attacker to forge a valid token using a publicly available RSA public key.

**Objective:** Explore algorithm confusion and investigate the importance of enforcing an expected signing algorithm and using the correct key type.

## Technologies

- Docker and Docker Compose
- Python / Flask
- Node.js / Express
- PHP
- Java / Spring Boot
- PyJWT
- jsonwebtoken
- firebase/php-jwt
- JJWT
- jwt_tool

## Running the Lab

Clone the repository:

```bash
git clone https://github.com/Zorograc/jwt-seminar.git
cd jwt-seminar
```

Start the applications:

```bash
docker compose up --build
```

The applications should then be accessible at:

| Application | URL |
|---|---|
| PyJWT | http://localhost:5000 |
| jsonwebtoken | http://localhost:3000 |
| php-jwt | http://localhost:8080 |
| jjwt | http://localhost:8081 |

## Repository Structure

```text
jwt-seminar/
├── attacks/          # JWT attack scripts and test cases
├── jjwt/             # Java / Spring Boot application
├── jsonwebtoken/     # Node.js / Express application
├── php-jwt/          # PHP application
├── pyjwt/             # Python / Flask application
├── jwt_tool/          # JWT testing utilities
├── docker-compose.yml
└── README.md
```

## Disclaimer

This project is intended for educational and security research purposes only.

All attack scenarios are designed to run against the deliberately created local test applications. Do not use these techniques against systems without explicit authorization.

The project does not claim to identify vulnerabilities in the JWT libraries themselves. Security outcomes depend on application configuration, implementation and token verification logic.