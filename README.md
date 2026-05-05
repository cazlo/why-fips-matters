# Why FIPS Matters

This repository exists to make a narrow point clearly:

FIPS-oriented crypto policy is not only about satisfying U.S. government frameworks such as FedRAMP or DoD requirements. Even for a modern security SaaS with no direct federal compliance scope, the same conservative choices often make practical engineering sense.

The historical reason is straightforward. TLS and cryptographic compatibility settings have a habit of turning into real attack paths later. Legacy protocol versions, weak cipher families, static RSA key exchange, export-era baggage, and overly broad compatibility profiles have repeatedly led to practical failures such as POODLE, FREAK, Logjam, DROWN, SWEET32, and ROBOT.

The practical reason is also straightforward. A security product handles high-value traffic: credentials, bearer tokens, session cookies, telemetry, findings, incident data, and administrative actions. For that kind of system, a narrow, boring, auditable crypto profile is usually the right default even when no regulator is forcing it.

## What this repo contains

- `tls_cipher_restrictions_security_saas.md`: a longer memo on TLS policy for modern security SaaS, with historical examples and concrete allowlist/denylist guidance.
- `tls-forward-secrecy-demo/`: a runnable lab that shows why `TLS_RSA_*` cipher suites are still a bad idea in TLS 1.2 even when they use AES-GCM.

## Core argument

The claim here is not that "FIPS solves everything" or that every commercial SaaS must adopt government policy wholesale.

The claim is smaller and more defensible:

- FIPS-era restrictions often encode hard-won lessons from real protocol failures.
- Modern Internet-facing security products should prefer strong defaults even when older options remain technically available.
- If TLS 1.2 must stay enabled for interoperability, it should be restricted to a small forward-secret AEAD allowlist.
- Static RSA key exchange, CBC suites, RC4, 3DES, export suites, and obsolete protocol versions are not harmless compatibility options.

In other words, "why FIPS matters" is partly a compliance story, but it is also a product-security story.

## Why the demo exists

The included lab demonstrates one specific point that still gets missed in practice: AES-GCM by itself does not guarantee a good TLS 1.2 configuration.

`TLS_RSA_WITH_AES_128_GCM_SHA256` looks modern at a glance because AES-GCM is modern. But it uses static RSA key exchange, which means it does not provide forward secrecy. If an attacker records traffic now and later obtains the server private key, previously captured sessions may become decryptable.

The demo compares that bad configuration with `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, which uses the same RSA certificate for authentication but ECDHE for ephemeral key agreement. The result is the practical distinction this repo is trying to highlight: narrow crypto policy is about limiting real failure modes, not just checking a box.

## Running the lab

From the demo directory:

```bash
cd tls-forward-secrecy-demo
docker compose build
docker compose up -d
docker compose exec tls-lab pytest -q
```

Or with make:

```bash
cd tls-forward-secrecy-demo
make test
```

The expected result is two passing tests:

- one proves that TLS 1.2 static RSA traffic can be decrypted later with only the server private key,
- one proves that the ECDHE version cannot.

## Audience

This repository is aimed at engineers, security reviewers, and product teams who need to explain why conservative TLS policy is still the right default for security-sensitive SaaS, even outside formal federal compliance programs.

## License

MIT. See `LICENSE`.