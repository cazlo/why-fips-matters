# Memo: TLS Cipher Restrictions for Modern Security SaaS

The goal is not “FIPS because magic.” The goal is to avoid exposing a security product through legacy TLS/SSL behavior that modern clients do not need. A security product should not weaken its Internet-facing transport posture to support obsolete clients, deprecated operating systems, or broken middleboxes.

As of 2026, this is an easier position to defend: Windows 10 support ended on October 14, 2025, and Windows 8.1 support ended on January 10, 2023. Microsoft no longer provides normal security fixes for those platforms. Supporting very old TLS behavior for clients in that class is not a product requirement; it is inherited risk.

References:

- Microsoft Windows 10 end of support: <https://support.microsoft.com/en-us/windows/windows-10-support-has-ended-on-october-14-2025-2ca8b313-1946-43d3-b55c-2b95b107f281>
- Microsoft Windows 8.1 end of support: <https://support.microsoft.com/en-us/windows/windows-8-1-support-ended-on-january-10-2023-3cfd4cde-f611-496a-8057-923fba401e93>

## Summary

For modern SaaS security products, we should prefer **TLS 1.3** and use **TLS 1.2 only where there is a specific interoperability need**. If TLS 1.2 is enabled, it should be restricted to a small AEAD-only, forward-secret profile.

This is not theoretical. TLS has a long history where optional legacy compatibility later became a practical exploit path. The impact is not abstract “crypto weakness”; the impact can be:

- recovering session cookies,
- stealing API tokens,
- reading credentials in transit,
- decrypting sensitive customer data,
- impersonating a server,
- modifying traffic in a man-in-the-middle position,
- weakening confidence in a product that is supposed to protect customers.

For a security product, even a “hard to exploit” TLS weakness matters more than it might for a random marketing site because customers may send logs, detections, incident data, credentials, tokens, admin actions, or sensitive telemetry through the service.

## Vulnerability / protocol history

| Crypto / feature | Example vuln / exploit | Year disclosed | Affected SSL/TLS versions | What the exploit did | Practical attacker impact | General exploit difficulty |
|---|---:|---:|---|---|---|---|
| **CBC mode in TLS/DTLS** | Lucky13 | 2013 | TLS/DTLS with CBC-mode cipher suites, mostly TLS 1.0–1.2 era | Timing/padding-oracle style plaintext recovery against CBC-mode TLS/DTLS. | Can expose protected plaintext such as cookies, bearer tokens, credentials, request bodies, or customer telemetry if the attacker can observe and influence enough traffic. | Generally hard. Requires MITM position, many carefully measured requests, low-noise timing conditions, and vulnerable implementation behavior. Still important because it represents a fragile class of protocol design. |
| **CBC mode in SSL 3.0 + downgrade fallback** | POODLE | 2014 | SSL 3.0 directly; TLS clients/servers indirectly if attacker can force fallback | Network attacker can force downgrade to SSL 3.0 and calculate plaintext of secure connections. | Can recover secrets such as session cookies, enabling account/session takeover. For SaaS consoles, that could mean access to dashboards, admin workflows, or customer data. | Moderate in the right conditions. Requires MITM position and ability to trigger downgrade/fallback and repeated victim requests, historically practical on hostile Wi-Fi or controlled networks. |
| **RC4 stream cipher** | RC4 NOMORE | 2015 | Any SSL/TLS version that negotiates RC4 | Practical cookie/plaintext recovery from repeated RC4-encrypted sessions. | Can recover repeatedly transmitted secrets such as cookies. That can enable session hijack, impersonation, and access to protected SaaS data. | Moderate to hard. Requires large volumes of repeated encrypted requests and attacker ability to induce traffic, but researchers demonstrated practical cookie recovery against real devices. |
| **RC4 stream cipher** | RFC 7465 prohibition | 2015 | Applies to all TLS versions | IETF formally prohibited RC4 cipher suites because RC4 no longer provided sufficient TLS security. | If RC4 is still negotiable, scanners and attackers can identify the service as permitting a cipher family known to leak information. This creates avoidable confidentiality and trust risk. | Varies by attack scenario, but sufficiently practical that IETF required TLS clients and servers never negotiate RC4. |
| **RSA_EXPORT / export-grade RSA** | FREAK | 2015 | SSL/TLS deployments accepting RSA_EXPORT suites | MITM forces weakened export-grade RSA, then breaks it to read or manipulate traffic. | Enables a network attacker to downgrade encryption, decrypt traffic, steal credentials/tokens, and potentially modify SaaS traffic in transit. | Moderate where vulnerable. Requires MITM position and server/client support for export-grade behavior; once downgraded, export RSA was intentionally weak enough to be breakable. |
| **DHE_EXPORT / weak finite-field DH** | Logjam | 2015 | TLS 1.2 and earlier with DHE_EXPORT or weak/common DH groups | MITM downgrade to 512-bit export DH; broader passive-decryption risk for common weak DH groups. | Enables reading and modifying traffic after downgrade. In a security product, that could expose alert data, logs, environment metadata, integration secrets, or admin actions. | Moderate for export-grade DH. Harder for 1024-bit common groups, but potentially within nation-state capability according to the Logjam researchers. Avoiding weak/common finite-field DH removes the class. |
| **SSLv2 support + RSA key reuse** | DROWN | 2016 | Modern TLS endpoints if same cert/key was also exposed via SSLv2 | Decrypt modern TLS by abusing obsolete SSLv2 support elsewhere. | A forgotten SSLv2 endpoint or reused certificate/private key can compromise traffic that appears to use modern TLS. This can expose sensitive SaaS traffic and undermine trust in key management. | Moderate to high depending on server behavior. Requires access to a server that supports SSLv2 with the same key, but Internet-wide exposure was large at disclosure. |
| **64-bit block ciphers, especially 3DES/TDEA** | SWEET32 | 2016 | TLS sessions negotiating 3DES or other 64-bit block ciphers | Birthday-bound collision attack against long-lived sessions; cookie recovery demonstrated. | Can recover cookies or repeated secrets from high-volume/long-lived sessions. Security SaaS often has long-lived browser sessions, agents, collectors, APIs, and telemetry streams, which makes this risk more relevant. | Hard but practical in lab conditions. Requires large traffic volume under one key and repeated secret material; the risk increases for long-lived/high-volume connections. |
| **RSA PKCS#1 v1.5 key transport / static RSA** | ROBOT | 2017 | TLS stacks still supporting RSA encryption key exchange, mostly TLS 1.2 and earlier | Bleichenbacher-style oracle enabling traffic decryption or server impersonation in some cases. | Can allow decryption of captured TLS sessions when RSA key exchange is used, and in some cases server impersonation/MITM. Lack of forward secrecy also means later key exposure can compromise previously captured traffic. | Varies. Some vulnerable implementations were directly exploitable; others were harder. Still severe enough because the oracle class has reappeared repeatedly over decades. |
| **DH-based ciphersuites with secret reuse** | Raccoon | 2020 | DH-based TLS connections; practically TLS 1.2-and-earlier style exposure | Timing attack that can allow pre-master secret recovery under specific conditions. | Can allow eavesdropping on encrypted communications if DH secret reuse and timing conditions align. For SaaS, this could expose API traffic, credentials, telemetry, or administrative requests. | Generally hard. Requires specific DH behavior, secret reuse, timing side channel, and network conditions. Its value as evidence is less “easy exploit” and more “older TLS/DH knobs are fragile and unnecessary.” |

References:

- Lucky13: <https://www.isg.rhul.ac.uk/tls/Lucky13.html>
- Google POODLE disclosure: <https://security.googleblog.com/2014/10/this-poodle-bites-exploiting-ssl-30.html>
- RC4 NOMORE: <https://www.rc4nomore.com/>
- RFC 7465, Prohibiting RC4 Cipher Suites: <https://www.rfc-editor.org/rfc/rfc7465.html>
- FREAK attack: <https://freakattack.com/>
- Logjam attack: <https://weakdh.org/>
- DROWN attack: <https://drownattack.com/>
- SWEET32: <https://sweet32.info/>
- ROBOT attack: <https://robotattack.org/>
- NVD CVE-2020-1968 / Raccoon: <https://nvd.nist.gov/vuln/detail/CVE-2020-1968>

## Why TLS 1.3 is different

TLS 1.3 effectively validates the “narrow the crypto menu” approach. RFC 8446 pruned legacy symmetric algorithms so that the remaining algorithms are AEAD-based, removed static RSA and static Diffie-Hellman key exchange, and made public-key key exchange forward-secret by default. TLS 1.3 cipher suites are also defined differently from TLS 1.2 cipher suites and cannot be used interchangeably.

The one major TLS 1.3 caveat is **0-RTT**. RFC 8446 explicitly warns that 0-RTT data is not forward secret and has no guarantee of non-replay between connections. For most SaaS applications, TLS 1.3 should be enabled, but **0-RTT should remain disabled unless there is a specific reviewed use case**.

References:

- RFC 8446, TLS 1.3: <https://www.rfc-editor.org/rfc/rfc8446.html>
- RFC 8446, 0-RTT warning: <https://www.rfc-editor.org/rfc/rfc8446.html#section-2.3>

## Recommended policy

For modern public-facing security SaaS:

```text
Enable:
- TLS 1.3
- TLS 1.2 only where interoperability requires it

TLS 1.3 allowlist:
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384

TLS 1.2 allowlist:
- ECDHE_RSA_WITH_AES_128_GCM_SHA256
- ECDHE_RSA_WITH_AES_256_GCM_SHA384
- ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
```

Explicitly disable:

```text
- SSLv2
- SSLv3
- TLS 1.0
- TLS 1.1
- RC4
- DES / 3DES / TDEA
- CBC-mode TLS cipher suites
- EXPORT suites
- NULL cipher suites
- anonymous DH
- static RSA key exchange: TLS_RSA_*
- static DH / static ECDH
- weak finite-field DH groups
- MD5 signatures
- SHA-1 signatures
- RSA keys smaller than 2048 bits
- TLS 1.3 0-RTT unless explicitly reviewed
```

## TLS 1.2 decision

There is still one practical reason to keep TLS 1.2: **interoperability**.

That may matter for:

- older B2B API clients,
- older Java or .NET runtimes,
- enterprise TLS inspection appliances,
- old agents or collectors,
- partner integrations that cannot yet negotiate TLS 1.3.

But this should be treated as an exception, not the default. NIST SP 800-52 Rev. 2 says TLS 1.2 may be disabled on TLS 1.3-capable servers when TLS 1.2 is not needed for interoperability.

Reference:

- NIST SP 800-52 Rev. 2: <https://csrc.nist.gov/pubs/sp/800/52/r2/final>

For a new security SaaS in 2026, the default should be:

```text
TLS 1.3 preferred.
TLS 1.2 allowed only with a narrow AEAD + ECDHE profile.
No TLS 1.1 or older.
No legacy cipher suites.
No downgrade baggage.
No 0-RTT unless explicitly reviewed.
```

## Bottom line

Cipher-suite selection is not compliance theater. It is a product-security control.

A modern security product should not preserve obsolete TLS behavior to support obsolete client environments. If a customer is still relying on Windows 8-era systems, unsupported browsers, or broken TLS middleboxes in 2026, that is not a reason to weaken the default Internet-facing posture of the product. At most, it is a documented exception path with explicit risk acceptance.

For the default public SaaS posture, the correct baseline is narrow, modern, auditable, and boring:

```text
TLS 1.3 first.
TLS 1.2 only where needed.
AEAD only.
Forward secrecy required.
No legacy crypto.
No weak downgrade paths.
No compatibility exceptions without risk acceptance.
```

---

# Appendix A — Exact allowlist for modern security SaaS

The defensible implementation stance is:

> **Do not primarily maintain a denylist. Use a strict allowlist.**  
> Denylists are for scanners, exception reviews, and “make sure this never shows up” guardrails.

IANA is the canonical registry for TLS cipher-suite names. OpenSSL, Java, Windows/SChannel, AWS, Envoy, nginx, HAProxy, and scanners may expose slightly different names or policy syntax, but the IANA names are the clean reference point.

Reference:

- IANA TLS Parameters registry: <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml>

## Preferred baseline

| TLS version | Hex | IANA cipher suite |
|---|---:|---|
| TLS 1.3 | `0x1301` | `TLS_AES_128_GCM_SHA256` |
| TLS 1.3 | `0x1302` | `TLS_AES_256_GCM_SHA384` |
| TLS 1.2 | `0xC02B` | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` |
| TLS 1.2 | `0xC02C` | `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` |
| TLS 1.2 | `0xC02F` | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` |
| TLS 1.2 | `0xC030` | `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` |

That is the clean “boring security product” profile.

For **FedRAMP/FIPS-scoped** endpoints, do not include ChaCha20-Poly1305 in the default allowlist. For **commercial-only** endpoints, `TLS_CHACHA20_POLY1305_SHA256` may be a reasonable exception, but it should be intentional, not accidental.

| TLS version | Hex | IANA cipher suite | Recommendation |
|---|---:|---|---|
| TLS 1.3 | `0x1303` | `TLS_CHACHA20_POLY1305_SHA256` | Optional commercial-only exception; not default FedRAMP/FIPS profile |

---

# Appendix B — Exact denylist categories, ordered by risk

## 1. Disable old protocol versions entirely

These are not cipher suites, but they should be blocked before cipher-suite negotiation matters.

```text
SSLv2
SSLv3
TLSv1.0
TLSv1.1
```

For modern security SaaS in 2026, these should be non-negotiable disables.

**Known attack examples:** POODLE, DROWN, BEAST-era TLS 1.0 CBC issues, downgrade/fallback abuse.

**What this enables an attacker to do:** Old protocol support can let a network attacker force or exploit weaker negotiation paths, decrypt traffic, recover cookies, or abuse a forgotten legacy listener to weaken modern TLS. DROWN is the clearest operational lesson: even if real users do not use SSLv2, merely supporting it with reused key material can expose modern TLS sessions.

**General exploit difficulty:** Varies. Some attacks require MITM position and active downgrade behavior; others require finding a misconfigured legacy service sharing keys. The important point is that the risk is unnecessary. Modern security SaaS should not carry old protocol support for clients that should not exist in the supported customer baseline.

References:

- POODLE: <https://security.googleblog.com/2014/10/this-poodle-bites-exploiting-ssl-30.html>
- DROWN: <https://drownattack.com/>

---

## 2. NULL / no-encryption suites

These are catastrophic if enabled because they provide no confidentiality.

```text
TLS_NULL_WITH_NULL_NULL
TLS_RSA_WITH_NULL_MD5
TLS_RSA_WITH_NULL_SHA
TLS_RSA_WITH_NULL_SHA256
TLS_ECDH_ECDSA_WITH_NULL_SHA
TLS_ECDHE_ECDSA_WITH_NULL_SHA
TLS_ECDH_RSA_WITH_NULL_SHA
TLS_ECDHE_RSA_WITH_NULL_SHA
TLS_ECDH_anon_WITH_NULL_SHA
```

**Known attack examples:** This is less about a branded exploit and more about catastrophic misconfiguration. If negotiated, traffic is not encrypted.

**What this enables an attacker to do:** A passive network observer can read the protected application traffic directly. For a security SaaS, this could expose credentials, session cookies, API tokens, logs, detections, customer metadata, or administrative actions.

**General exploit difficulty:** Easy if the suite is actually negotiable and the attacker can observe traffic. There is no cryptanalysis needed because confidentiality is absent.

---

## 3. EXPORT-grade suites

These are the FREAK / Logjam-style “compatibility became downgrade target” suites.

```text
TLS_RSA_EXPORT_WITH_RC4_40_MD5
TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
TLS_RSA_EXPORT_WITH_DES40_CBC_SHA

TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA

TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
```

For scanners / policy engines, block anything matching:

```text
*_EXPORT_*
*EXPORT*
```

Logjam specifically involved `DHE_EXPORT` downgrade behavior in TLS 1.2 and earlier.

**Known attack examples:** FREAK and Logjam.

**What this enables an attacker to do:** A MITM can downgrade the connection to intentionally weakened export-grade cryptography, then break the weakened key exchange. That can allow reading traffic, stealing credentials or tokens, and modifying requests/responses in transit.

**General exploit difficulty:** Moderate where vulnerable. Requires MITM position and vulnerable client/server negotiation behavior. Once downgrade succeeds, the cryptography is intentionally weak enough to be practical to break.

References:

- FREAK: <https://freakattack.com/>
- Logjam: <https://weakdh.org/>
- NVD CVE-2015-4000: <https://nvd.nist.gov/vuln/detail/CVE-2015-4000>

---

## 4. RC4 suites

RC4 was formally prohibited for TLS by RFC 7465.

```text
TLS_RSA_WITH_RC4_128_MD5
TLS_RSA_WITH_RC4_128_SHA
TLS_RSA_EXPORT_WITH_RC4_40_MD5

TLS_DH_anon_WITH_RC4_128_MD5
TLS_DH_anon_EXPORT_WITH_RC4_40_MD5

TLS_ECDH_ECDSA_WITH_RC4_128_SHA
TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
TLS_ECDH_RSA_WITH_RC4_128_SHA
TLS_ECDHE_RSA_WITH_RC4_128_SHA
TLS_ECDH_anon_WITH_RC4_128_SHA

TLS_PSK_WITH_RC4_128_SHA
TLS_DHE_PSK_WITH_RC4_128_SHA
TLS_RSA_PSK_WITH_RC4_128_SHA
```

Block anything matching:

```text
*RC4*
*ARCFOUR*
```

**Known attack examples:** RC4 NOMORE; RFC 7465 prohibition.

**What this enables an attacker to do:** RC4 keystream biases can leak repeatedly encrypted plaintext. In web/SaaS scenarios, repeated cookies or tokens are the obvious target. Successful recovery can lead to session hijacking and account takeover.

**General exploit difficulty:** Moderate to hard. The attacker generally needs to induce and observe many repeated encrypted requests. However, practical cookie recovery was demonstrated, and the IETF prohibition reflects that the risk crossed from theoretical into operationally unacceptable.

References:

- RC4 NOMORE: <https://www.rc4nomore.com/>
- RFC 7465: <https://www.rfc-editor.org/rfc/rfc7465.html>

---

## 5. DES / 3DES / TDEA / 64-bit block cipher suites

These are SWEET32-class risk. SWEET32 showed that 64-bit block ciphers such as 3DES and Blowfish become unsafe at modern traffic volumes.

```text
TLS_RSA_WITH_DES_CBC_SHA
TLS_RSA_WITH_3DES_EDE_CBC_SHA

TLS_DH_DSS_WITH_DES_CBC_SHA
TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
TLS_DH_RSA_WITH_DES_CBC_SHA
TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA

TLS_DHE_DSS_WITH_DES_CBC_SHA
TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
TLS_DHE_RSA_WITH_DES_CBC_SHA
TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA

TLS_DH_anon_WITH_DES_CBC_SHA
TLS_DH_anon_WITH_3DES_EDE_CBC_SHA

TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA

TLS_PSK_WITH_3DES_EDE_CBC_SHA
TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA
TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA
```

Block anything matching:

```text
*DES*
*3DES*
*TDEA*
*EDE_CBC*
*DES40*
```

**Known attack examples:** SWEET32.

**What this enables an attacker to do:** With enough traffic under the same key, birthday-bound collisions can expose repeated secrets such as HTTP cookies. For SaaS security products, long-lived sessions, high-volume agent traffic, streaming telemetry, and persistent API clients can create the kind of traffic patterns that make old block-size assumptions unsafe.

**General exploit difficulty:** Hard but practical in controlled/lab conditions. The attacker needs to capture a large amount of traffic and usually needs repeated secret material. This is still unacceptable because the fix is simple: do not negotiate 64-bit block ciphers.

Reference:

- SWEET32: <https://sweet32.info/>

---

## 6. CBC-mode suites

CBC is the broad Lucky13 / POODLE / padding-oracle risk family. CBC is especially unnecessary for modern public SaaS because TLS 1.2 has AES-GCM and TLS 1.3 is AEAD-only. TLS 1.3 explicitly pruned legacy symmetric algorithms and kept AEAD algorithms.

Common AES-CBC suites to block:

```text
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA256

TLS_DHE_RSA_WITH_AES_128_CBC_SHA
TLS_DHE_RSA_WITH_AES_256_CBC_SHA
TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256

TLS_DHE_DSS_WITH_AES_128_CBC_SHA
TLS_DHE_DSS_WITH_AES_256_CBC_SHA
TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
TLS_DHE_DSS_WITH_AES_256_CBC_SHA256

TLS_DH_RSA_WITH_AES_128_CBC_SHA
TLS_DH_RSA_WITH_AES_256_CBC_SHA
TLS_DH_RSA_WITH_AES_128_CBC_SHA256
TLS_DH_RSA_WITH_AES_256_CBC_SHA256

TLS_DH_DSS_WITH_AES_128_CBC_SHA
TLS_DH_DSS_WITH_AES_256_CBC_SHA
TLS_DH_DSS_WITH_AES_128_CBC_SHA256
TLS_DH_DSS_WITH_AES_256_CBC_SHA256

TLS_DH_anon_WITH_AES_128_CBC_SHA
TLS_DH_anon_WITH_AES_256_CBC_SHA
TLS_DH_anon_WITH_AES_128_CBC_SHA256
TLS_DH_anon_WITH_AES_256_CBC_SHA256

TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384

TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384

TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384

TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
```

Also block non-AES CBC families unless you have an explicit legacy exception:

```text
*CBC*
*CAMELLIA*_CBC*
*ARIA*_CBC*
*SEED*_CBC*
*IDEA*_CBC*
*RC2*_CBC*
```

The clean SaaS stance is simpler:

```text
Block every TLS 1.2 suite containing _CBC_.
Allow only ECDHE + AES_GCM for TLS 1.2.
```

**Known attack examples:** Lucky13, POODLE, BEAST-era TLS 1.0 CBC issues.

**What this enables an attacker to do:** CBC-mode TLS weaknesses can enable plaintext recovery through timing or padding-oracle style attacks. The most valuable target is often a session cookie or bearer token, which can convert a transport-layer weakness into application account compromise.

**General exploit difficulty:** Usually hard to moderate depending on the exact vulnerability. The attacker often needs MITM position, many requests, chosen plaintext influence, downgrade/fallback behavior, or precise timing. The important engineering point is that CBC has a long history of fragile composition, while AES-GCM and TLS 1.3 avoid the class.

References:

- Lucky13: <https://www.isg.rhul.ac.uk/tls/Lucky13.html>
- POODLE: <https://security.googleblog.com/2014/10/this-poodle-bites-exploiting-ssl-30.html>
- RFC 8446, TLS 1.3: <https://www.rfc-editor.org/rfc/rfc8446.html>

---

## 7. Static RSA key-exchange suites

These are bad because they do not provide forward secrecy and are tied to ROBOT / Bleichenbacher-class history. TLS 1.3 removed static RSA key exchange.

Block TLS 1.2 suites beginning with:

```text
TLS_RSA_WITH_*
```

Examples:

```text
TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_GCM_SHA384

TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA256

TLS_RSA_WITH_3DES_EDE_CBC_SHA
TLS_RSA_WITH_RC4_128_SHA
TLS_RSA_WITH_RC4_128_MD5
TLS_RSA_WITH_NULL_SHA
TLS_RSA_WITH_NULL_SHA256
```

Important nuance: this does **not** mean “do not use RSA certificates.” It means do not use **static RSA key transport** cipher suites. This is okay:

```text
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
```

That uses RSA for authentication, but ECDHE for key agreement.

**Known attack examples:** ROBOT; broader Bleichenbacher / RSA PKCS#1 v1.5 oracle family.

**What this enables an attacker to do:** If RSA key transport is used and an oracle exists, attackers may decrypt sessions or impersonate the server in MITM scenarios. Separately, lack of forward secrecy means that if the server private key is compromised later, previously captured traffic may become decryptable.

**General exploit difficulty:** Varies widely by implementation. Some implementations expose practical oracles; others are harder. The class is severe because it has reappeared repeatedly since the original Bleichenbacher attack and because avoiding it is easy: use ECDHE.

References:

- ROBOT: <https://robotattack.org/>
- RFC 8446, TLS 1.3: <https://www.rfc-editor.org/rfc/rfc8446.html>

---

## 8. Anonymous DH / anonymous ECDH suites

These provide no real server authentication and are inappropriate for public SaaS.

```text
TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
TLS_DH_anon_WITH_RC4_128_MD5
TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
TLS_DH_anon_WITH_DES_CBC_SHA
TLS_DH_anon_WITH_3DES_EDE_CBC_SHA

TLS_DH_anon_WITH_AES_128_CBC_SHA
TLS_DH_anon_WITH_AES_256_CBC_SHA
TLS_DH_anon_WITH_AES_128_CBC_SHA256
TLS_DH_anon_WITH_AES_256_CBC_SHA256

TLS_DH_anon_WITH_AES_128_GCM_SHA256
TLS_DH_anon_WITH_AES_256_GCM_SHA384

TLS_ECDH_anon_WITH_NULL_SHA
TLS_ECDH_anon_WITH_RC4_128_SHA
TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
TLS_ECDH_anon_WITH_AES_128_CBC_SHA
TLS_ECDH_anon_WITH_AES_256_CBC_SHA
```

Block anything matching:

```text
*anon*
TLS_DH_anon_*
TLS_ECDH_anon_*
ADH
AECDH
```

**Known attack examples:** This is primarily a protocol-authentication failure rather than one branded exploit. Anonymous DH deliberately lacks certificate-based server authentication.

**What this enables an attacker to do:** A MITM can impersonate the server because the key exchange does not authenticate the peer. The connection may be encrypted to the attacker, not to the intended SaaS endpoint.

**General exploit difficulty:** Easy if a client/server actually negotiates anonymous DH and the attacker has MITM position. No cryptographic break is needed; the authentication property is missing by design.

---

## 9. Static DH / static ECDH suites

These are generally unnecessary, uncommon, and not the modern public Web/SaaS profile. Prefer ECDHE only.

```text
TLS_DH_DSS_WITH_AES_128_GCM_SHA256
TLS_DH_DSS_WITH_AES_256_GCM_SHA384
TLS_DH_RSA_WITH_AES_128_GCM_SHA256
TLS_DH_RSA_WITH_AES_256_GCM_SHA384

TLS_DH_DSS_WITH_AES_128_CBC_SHA
TLS_DH_DSS_WITH_AES_256_CBC_SHA
TLS_DH_RSA_WITH_AES_128_CBC_SHA
TLS_DH_RSA_WITH_AES_256_CBC_SHA

TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
```

Block prefixes:

```text
TLS_DH_DSS_*
TLS_DH_RSA_*
TLS_ECDH_ECDSA_*
TLS_ECDH_RSA_*
```

Allow only the ephemeral variants:

```text
TLS_ECDHE_RSA_*
TLS_ECDHE_ECDSA_*
```

And even then, only the AES-GCM variants listed in Appendix A.

**Known attack examples:** Not one single headline exploit in the same way as FREAK/Logjam, but this class lacks the forward-secret posture TLS 1.3 moved toward.

**What this enables an attacker to do:** Static DH/ECDH does not provide the same forward secrecy properties as ephemeral ECDHE. If long-term key material is compromised, captured traffic may be at greater risk.

**General exploit difficulty:** Depends on key compromise or implementation mistakes rather than a universal direct break. The operational point is that static DH/ECDH is unnecessary for modern public SaaS and should not be in the supported profile.

Reference:

- RFC 8446, TLS 1.3 removed static RSA/DH-style suites: <https://www.rfc-editor.org/rfc/rfc8446.html>

---

## 10. Finite-field DHE suites

This one is nuanced. `DHE_RSA_WITH_AES_*_GCM_*` is not inherently trash if parameters are strong, but in practice it creates avoidable operational risk: weak DH params, shared/common groups, Logjam/Raccoon-class history, slower handshakes, and more knobs to misconfigure.

For modern SaaS, block finite-field DHE and use ECDHE only.

```text
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
TLS_DHE_DSS_WITH_AES_256_GCM_SHA384

TLS_DHE_RSA_WITH_AES_128_CBC_SHA
TLS_DHE_RSA_WITH_AES_256_CBC_SHA
TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256

TLS_DHE_DSS_WITH_AES_128_CBC_SHA
TLS_DHE_DSS_WITH_AES_256_CBC_SHA
TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
```

Block prefixes:

```text
TLS_DHE_RSA_*
TLS_DHE_DSS_*
DHE-*
```

Exception path, only if finite-field DH is truly required:

```text
Require FFDHE >= 2048-bit.
Reject custom weak DH params.
Prefer RFC 7919 named FFDHE groups.
Document the reason ECDHE was insufficient.
```

But for a new security SaaS: do not bother. Use ECDHE.

**Known attack examples:** Logjam and Raccoon.

**What this enables an attacker to do:** Weak/export DHE can allow downgrade and traffic decryption/modification. DH secret reuse/timing weaknesses can potentially expose session secrets. Even when exploitation is difficult, these modes add operational risk that ECDHE avoids.

**General exploit difficulty:** Logjam against export-grade DHE was moderate when vulnerable; attacks against larger/common groups are much harder but may be plausible for powerful adversaries. Raccoon is generally hard and condition-dependent. For modern SaaS, the right lesson is that finite-field DHE creates unnecessary misconfiguration surface.

References:

- Logjam: <https://weakdh.org/>
- Raccoon / CVE-2020-1968: <https://nvd.nist.gov/vuln/detail/CVE-2020-1968>

---

## 11. PSK / SRP suites

These are usually inappropriate for browser-facing SaaS and can create confusing auth/key-management paths.

Block prefixes:

```text
TLS_PSK_*
TLS_DHE_PSK_*
TLS_RSA_PSK_*
TLS_ECDHE_PSK_*
TLS_SRP_*
```

Common examples:

```text
TLS_PSK_WITH_AES_128_GCM_SHA256
TLS_PSK_WITH_AES_256_GCM_SHA384
TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
TLS_SRP_SHA_WITH_AES_128_CBC_SHA
TLS_SRP_SHA_WITH_AES_256_CBC_SHA
TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
```

TLS 1.3 uses PSK internally for resumption, so this appendix item is about legacy TLS 1.2 PSK/SRP cipher-suite families, not normal TLS 1.3 session resumption.

**Known attack examples:** This category is less about a single universal branded exploit and more about inappropriate authentication architecture for public SaaS.

**What this enables an attacker to do:** Poorly managed PSK/SRP deployments can create weak shared-secret management, confusing authentication boundaries, and hard-to-audit exceptions. If PSKs are weak, reused, leaked, or improperly scoped, compromise can affect multiple clients or sessions.

**General exploit difficulty:** Depends heavily on implementation and key management. The safest SaaS posture is to avoid these suites entirely unless there is a specific, reviewed, non-browser protocol need.

---

# Appendix C — Scanner-friendly deny patterns

For policy review / scanner logic, the practical block patterns are:

```text
Protocol:
- SSLv2
- SSLv3
- TLSv1.0
- TLSv1.1

Cipher-suite substrings / prefixes:
- *_NULL_*
- *EXPORT*
- *RC4*
- *DES*
- *3DES*
- *TDEA*
- *_CBC_*
- TLS_RSA_WITH_*
- TLS_DH_anon_*
- TLS_ECDH_anon_*
- TLS_DH_DSS_*
- TLS_DH_RSA_*
- TLS_ECDH_ECDSA_*
- TLS_ECDH_RSA_*
- TLS_DHE_RSA_*
- TLS_DHE_DSS_*
- TLS_PSK_*
- TLS_DHE_PSK_*
- TLS_RSA_PSK_*
- TLS_ECDHE_PSK_*
- TLS_SRP_*
```

OpenSSL-style negative selectors vary by version, but the rough conceptual equivalent is:

```text
!aNULL:!eNULL:!EXPORT:!LOW:!RC4:!3DES:!DES:!MD5:!PSK:!SRP:!DSS:!kRSA:!kDH:!CBC
```

OpenSSL’s cipher tooling exists specifically to convert textual cipher lists into ordered cipher preferences, and OpenSSL versions differ in naming/policy behavior, so verify the resulting effective list with `openssl ciphers -V`.

Reference:

- OpenSSL `ciphers` command: <https://docs.openssl.org/3.3/man1/openssl-ciphers/>

# Appendix D — Practical implementation rule

Do this:

```text
Allow only:
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
```

Do **not** try to enumerate every possible bad suite forever. The IANA registry is large, historical, and full of things no modern SaaS should negotiate. The safer engineering control is:

```text
Default deny.
Explicit allowlist.
Regression test negotiated TLS.
Scanner gate in CI/CD.
Runtime observability for negotiated protocol/cipher.
Exception process for anything outside the allowlist.
```
