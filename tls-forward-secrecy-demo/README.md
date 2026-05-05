# TLS 1.2 Forward Secrecy Demo: `TLS_RSA_*` vs `TLS_ECDHE_RSA_*`

This lab demonstrates why a modern security SaaS should block static RSA key-exchange cipher suites such as:

```text
TLS_RSA_WITH_AES_128_GCM_SHA256
```

Even though that suite uses AES-GCM, it does **not** provide forward secrecy. If an attacker records traffic today and later obtains the server private key, the captured TLS 1.2 traffic can be decrypted.

The comparison suite is:

```text
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

That suite still uses an RSA certificate for server authentication, but it uses ephemeral ECDHE for key agreement. If an attacker later obtains the server private key, previously captured traffic remains protected because the server certificate key is not enough to reconstruct the ephemeral session keys.

## Why this matters

For public security SaaS, the risk is not theoretical. If a product accepts static RSA key-exchange suites, then a later private-key compromise can expose earlier captured traffic. Depending on what crosses the TLS channel, that could include:

- session cookies,
- bearer tokens,
- API keys,
- credentials,
- customer telemetry,
- incident data,
- detection results,
- administrative actions.

The important distinction is:

```text
Bad for modern SaaS:
TLS_RSA_WITH_AES_128_GCM_SHA256

Good TLS 1.2 fallback profile:
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

`RSA_WITH_AES_GCM` can look modern because AES-GCM is modern. The problem is the `TLS_RSA_*` key exchange. It lacks forward secrecy.

## Cloud policy examples

This demo is relevant because static RSA AES-GCM suites still appear in real managed cloud TLS policy sets and legacy/default-by-creation-path configurations.

Examples to verify in vendor documentation:

- AWS Elastic Load Balancing SSL policies include `TLS_RSA_WITH_AES_128_GCM_SHA256` / OpenSSL `AES128-GCM-SHA256` in older policies such as `ELBSecurityPolicy-2016-08`.
- AWS documents that ALB listener defaults can differ depending on creation path, with non-console automation historically able to inherit older policies.
- Azure Application Gateway older predefined policies include `TLS_RSA_WITH_AES_128_GCM_SHA256`; newer 2022 policies remove it.

The policy conclusion is not “cloud is insecure.” The conclusion is:

```text
Cloud-managed TLS policies are general-purpose.
Security-product TLS policies should be explicit, narrow, and regression-tested.
```

## What the lab proves

The pytest suite starts two local TLS 1.2 servers with the same RSA certificate and private key:

| Server | IANA cipher suite | OpenSSL cipher name | Forward secrecy? |
|---|---|---|---|
| bad | `TLS_RSA_WITH_AES_128_GCM_SHA256` | `AES128-GCM-SHA256` | No |
| good | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | `ECDHE-RSA-AES128-GCM-SHA256` | Yes |

For each server, the test:

1. Starts a local TLS 1.2 server.
2. Sends an HTTPS request with a fake bearer token.
3. Captures the traffic to a pcap.
4. Simulates later compromise of the server private key.
5. Attempts to decrypt the pcap with `tshark` using only the server private key.

Expected result:

```text
TLS_RSA_WITH_AES_128_GCM_SHA256:
  Decryption succeeds.
  The fake Authorization header is visible.

TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
  Decryption fails.
  The fake Authorization header is not visible.
```

## Requirements

- Docker
- Docker Compose v2

No external target is attacked. The lab runs only against local services inside a container.

## Run

```bash
docker compose build
docker compose up -d
```

Then run the tests:

```bash
docker compose exec tls-lab pytest -q
```

You should see two passing tests.

## Inspect the generated pcaps

The tests write pcaps here inside the container:

```text
/workspace/pcaps/
```

Copy them out if desired:

```bash
docker cp tls-forward-secrecy-demo:/workspace/pcaps ./pcaps
```

## Manually verify negotiated ciphers

Static RSA case:

```bash
docker compose exec tls-lab openssl s_client \
  -connect 127.0.0.1:9443 \
  -tls1_2 \
  -cipher 'AES128-GCM-SHA256:@SECLEVEL=0' \
  -servername localhost \
  -brief
```

ECDHE case:

```bash
docker compose exec tls-lab openssl s_client \
  -connect 127.0.0.1:9444 \
  -tls1_2 \
  -cipher 'ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0' \
  -servername localhost \
  -brief
```

The pytest automation normally starts and stops these servers for you, so the manual commands are mostly useful while debugging.

## Implementation notes

OpenSSL names differ from IANA names:

| IANA | OpenSSL | Hex |
|---|---|---|
| `TLS_RSA_WITH_AES_128_GCM_SHA256` | `AES128-GCM-SHA256` | `0x009C` |
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | `ECDHE-RSA-AES128-GCM-SHA256` | `0xC02F` |

The test uses `@SECLEVEL=0` because modern OpenSSL builds may otherwise reject old or undesirable key-exchange modes. That is intentional: this is a vulnerable lab demonstrating why the old mode should be blocked.

## Policy takeaway

The right production control is not a giant denylist. It is an allowlist:

```text
TLS 1.3:
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384

TLS 1.2 only if needed:
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
```

Block `TLS_RSA_WITH_*` even when the symmetric cipher is AES-GCM.

## Vendor references

- AWS CloudFront supported protocols and ciphers: <https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html>
- AWS ELB SSL policies: <https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html>
- Azure Application Gateway SSL policy overview: <https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-ssl-policy-overview>
- Azure Front Door TLS policy: <https://learn.microsoft.com/en-us/azure/frontdoor/standard-premium/tls-policy>
