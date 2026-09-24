# CVSS Guide: Metrics, Versions and Scoring Explained

## What is CVSS?

The **Common Vulnerability Scoring System (CVSS)** is an open standard for assessing the severity of security vulnerabilities. Maintained by [FIRST.org](https://www.first.org/cvss/), it provides a consistent, vendor-neutral framework to communicate the characteristics and severity of software vulnerabilities.

A CVSS score ranges from **0.0 to 10.0**, where higher values indicate greater severity. The score is derived from a set of metrics that capture how a vulnerability can be exploited and what impact it has.

CVSS is widely used by:

- **Security vendors** to rate CVEs in their advisories
- **Patch management teams** to prioritize remediation
- **Compliance frameworks** (PCI-DSS, HIPAA, ISO 27001) to assess risk
- **Bug bounty programs** to determine payout tiers

> CVSS is a *severity* measure, not a *risk* measure. It does not account for your specific environment, asset value, or threat landscape — that is the job of your risk management process.

---

## Severity Ratings

All CVSS versions map scores to a qualitative severity rating:

| Score | Severity | Typical Action |
|-------|----------|----------------|
| 0.0 | None | No action required |
| 0.1 – 3.9 | Low | Fix in next scheduled release |
| 4.0 – 6.9 | Medium | Fix within 60–90 days |
| 7.0 – 8.9 | High | Fix within 30 days |
| 9.0 – 10.0 | Critical | Fix immediately |

> CVSS v2.0 does not have the **Critical** rating — scores 7.0–10.0 are all **High**.

---

## CVSS v2.0

Released in **2007**, CVSS v2.0 was the first widely adopted version. It uses a formula based on three groups of metrics.

### Base Metrics

Base metrics capture the intrinsic characteristics of a vulnerability that are constant over time and across environments.

#### Attack Vector (AV)

How the vulnerability is exploited:

| Value | Name | Description |
|-------|------|-------------|
| N | Network | Exploitable remotely over the network |
| A | Adjacent | Requires access to the local network (LAN, VPN) |
| L | Local | Requires local access (shell, physical) |

#### Access Complexity (AC)

How complex the attack is once the attacker has access:

| Value | Name | Description |
|-------|------|-------------|
| L | Low | No special conditions required |
| M | Medium | Requires specific configuration or timing |
| H | High | Requires significant preparation or rare conditions |

#### Authentication (Au)

Number of times the attacker must authenticate:

| Value | Name | Description |
|-------|------|-------------|
| N | None | No authentication required |
| S | Single | Must authenticate once |
| M | Multiple | Must authenticate multiple times |

#### Impact Metrics (C / I / A)

Confidentiality, Integrity, and Availability impact on the affected system:

| Value | Name | Description |
|-------|------|-------------|
| N | None | No impact |
| P | Partial | Reduced performance or partial data exposure |
| C | Complete | Total loss of protection |

### Temporal Metrics

Temporal metrics change over time as new information becomes available. They are optional and default to **ND** (Not Defined).

| Metric | Description |
|--------|-------------|
| **E** Exploitability | Availability and reliability of exploit code |
| **RL** Remediation Level | Availability of a fix or workaround |
| **RC** Report Confidence | Degree of confidence in the existence of the vulnerability |

### Environmental Metrics

Environmental metrics reflect the specific characteristics of an organization's environment. They are optional and default to **ND**.

| Metric | Description |
|--------|-------------|
| **CDP** Collateral Damage Potential | Potential for physical damage or revenue loss |
| **TD** Target Distribution | Proportion of vulnerable systems |
| **CR / IR / AR** | Confidentiality, Integrity, Availability requirements |

### Example: CVE-2017-5638 (Apache Struts RCE)

```
AV:N/AC:L/Au:N/C:C/I:C/A:C
Score: 10.0 — High
```

- **AV:N** — Exploitable over the network
- **AC:L** — No special conditions required
- **Au:N** — No authentication needed
- **C:C / I:C / A:C** — Complete loss of confidentiality, integrity, availability

---

## CVSS v3.0 and v3.1

CVSS v3.0 was released in **2015**, followed by v3.1 in **2019** (a clarification update with no formula changes). v3.x introduced significant improvements over v2:

- **Scope** metric to capture cross-component impact
- **Privileges Required** replaces Authentication
- **User Interaction** becomes an explicit metric
- **Critical** severity added (9.0–10.0)
- Network vs Adjacent distinction refined

### Base Metrics

#### Attack Vector (AV)

| Value | Name | Description |
|-------|------|-------------|
| N | Network | Remotely exploitable |
| A | Adjacent | Requires adjacent network access |
| L | Local | Requires local access |
| P | Physical | Requires physical access to device |

#### Attack Complexity (AC)

| Value | Name | Description |
|-------|------|-------------|
| L | Low | No special conditions or preparation needed |
| H | High | Requires specific conditions (race condition, non-default config) |

#### Privileges Required (PR)

| Value | Name | Description |
|-------|------|-------------|
| N | None | No privileges required |
| L | Low | Standard user privileges |
| H | High | Administrator/root privileges |

> **Note:** When Scope is Changed, PR:L and PR:H scores are boosted because elevated-privilege exploits in a changed-scope context are more dangerous.

#### User Interaction (UI)

| Value | Name | Description |
|-------|------|-------------|
| N | None | No user interaction required |
| R | Required | Requires a user to perform an action (click link, open file) |

#### Scope (S)

The **Scope** metric is new in v3.x and captures whether the vulnerability can impact components beyond the vulnerable one.

| Value | Name | Description |
|-------|------|-------------|
| U | Unchanged | Impact is limited to the vulnerable component |
| C | Changed | Impact extends to other components (e.g., hypervisor escape, privilege escalation to OS) |

#### Impact Metrics (C / I / A)

| Value | Name | Description |
|-------|------|-------------|
| N | None | No impact |
| L | Low | Partial or limited impact |
| H | High | Total or severe impact |

### Temporal Metrics

Optional. Default: **X** (Not Defined).

| Metric | Values | Description |
|--------|--------|-------------|
| **E** Exploit Code Maturity | X, U, P, F, H | Maturity of available exploit code |
| **RL** Remediation Level | X, O, T, W, U | Availability of official fix, workaround |
| **RC** Report Confidence | X, U, R, C | Confidence in vulnerability existence |

### Environmental Metrics

Optional. Allow organizations to tune the score for their specific context. Default: **X**.

| Metric | Description |
|--------|-------------|
| **CR / IR / AR** | Confidentiality, Integrity, Availability requirements |
| **MAV, MAC, MPR, MUI, MS, MC, MI, MA** | Modified versions of all base metrics |

### v3.0 vs v3.1 Differences

v3.1 introduced no formula changes. The update focused on:

- Clearer definitions for existing metrics (especially AV:A and AV:N)
- Improved guidance for scoring privilege escalation in scope-changed scenarios
- Better examples in the official specification

### Example: CVE-2021-44228 (Log4Shell)

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
Score: 10.0 — Critical
```

- **AV:N** — Exploitable over the internet
- **AC:L** — Trivial to exploit, no special conditions
- **PR:N** — No authentication required
- **UI:N** — No user action needed
- **S:C** — Scope Changed — attacker escapes the JVM context
- **C:H / I:H / A:H** — Full system compromise possible

---

## CVSS v4.0

Released in **November 2023**, CVSS v4.0 is a major redesign addressing fundamental limitations of v3.x:

- Splits impact into **Vulnerable System** and **Subsequent System**
- Adds **Attack Requirements** (AT) to model prerequisite conditions
- Introduces **Supplemental metrics** for additional context
- Introduces **Threat metrics** (replaces Temporal)
- Uses a lookup-table scoring model instead of a formula

### Base Metrics

#### Attack Vector (AV)

Same values as v3.1: **N, A, L, P**

#### Attack Complexity (AC)

| Value | Name | Description |
|-------|------|-------------|
| L | Low | No specialized conditions needed |
| H | High | Requires significant attacker effort or specific circumstances |

#### Attack Requirements (AT) — New in v4.0

Captures prerequisite conditions **outside attacker control**:

| Value | Name | Description |
|-------|------|-------------|
| N | None | No specific deployment or configuration required |
| P | Present | Requires a specific system configuration or deployment condition |

#### Privileges Required (PR)

Same values as v3.1: **N, L, H**

#### User Interaction (UI)

| Value | Name | Description |
|-------|------|-------------|
| N | None | No user interaction |
| P | Passive | User interaction required but passive (victim browses to page) |
| A | Active | User must explicitly take action (open file, approve dialog) |

#### Vulnerable System Impact (VC / VI / VA)

Impact on the **directly vulnerable component**:

| Value | Description |
|-------|-------------|
| H | High — complete loss |
| L | Low — partial or limited |
| N | None |

#### Subsequent System Impact (SC / SI / SA)

Impact on **other systems or components** beyond the vulnerable one:

| Value | Description |
|-------|-------------|
| H | High — significant impact on other systems |
| L | Low — limited impact on other systems |
| N | None |

This replaces the v3.x **Scope** concept with a more granular model.

### Threat Metrics (replaces Temporal)

| Metric | Values | Description |
|--------|--------|-------------|
| **E** Exploit Maturity | X, A, P, U | State of available exploitation techniques |

- **X** — Not Defined (default)
- **A** — Attacked — active exploitation in the wild
- **P** — Proof-of-Concept — PoC exists but not widely exploited
- **U** — Unreported — no known exploitation

### Environmental Metrics

Same concept as v3.x — modified base metrics + CIA requirements. Default: **X**.

### Supplemental Metrics — New in v4.0

These do **not affect the score** but provide additional context:

| Metric | Description |
|--------|-------------|
| **S** Safety | Impact on safety systems (physical harm potential) |
| **AU** Automatable | Can the exploit be automated at scale? |
| **R** Recovery | How easily can the system recover after exploitation? |
| **V** Value Density | How valuable are the assets at risk? |
| **RE** Response Effort | How difficult is the vulnerability to respond to? |
| **U** Provider Urgency | Vendor-assigned urgency classification |

### Example: Hypothetical Network RCE in v4.0

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
Score: 10.0 — Critical
```

### Key Changes from v3.1

| Aspect | v3.1 | v4.0 |
|--------|------|------|
| Impact model | Single scope (Unchanged/Changed) | Dual: Vulnerable + Subsequent System |
| User Interaction | None / Required | None / Passive / Active |
| Attack conditions | AC only | AC + AT (Attack Requirements) |
| Temporal → Threat | 3 metrics (E, RL, RC) | 1 metric (E) |
| Supplemental info | None | 6 supplemental metrics |
| Scoring method | Mathematical formula | Lookup table (macrovectors) |

---

## Version Comparison

| Feature | v2.0 | v3.0/3.1 | v4.0 |
|---------|------|----------|------|
| Release year | 2007 | 2015/2019 | 2023 |
| Base metrics | 6 | 8 | 11 |
| Max severity label | High | Critical | Critical |
| Scope concept | No | Scope (U/C) | Dual system impact |
| Physical AV | No | Yes | Yes |
| User Interaction | No | Yes | Yes (3 values) |
| Attack Requirements | No | No | Yes |
| Supplemental metrics | No | No | Yes |
| Scoring method | Formula | Formula | Lookup table |

---

## Metric Quick Reference

### v3.1 Full Vector Structure

```
CVSS:3.1 / AV:_ / AC:_ / PR:_ / UI:_ / S:_ / C:_ / I:_ / A:_
```

Base metrics in order: Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality, Integrity, Availability.

### v4.0 Full Vector Structure

```
CVSS:4.0 / AV:_ / AC:_ / AT:_ / PR:_ / UI:_ / VC:_ / VI:_ / VA:_ / SC:_ / SI:_ / SA:_
```

---

## CVSS Guru Services

### Calculator

The CVSS Guru calculator supports all four versions simultaneously. As you select metrics, the score updates in real time using HTMX partial updates — no page reload.

**Features:**
- Live CVSS score calculation for v2.0, v3.0, v3.1, and v4.0
- Metric descriptions on hover
- Shareable link for any score
- Automatic value conversion when switching versions

**How to use:**
1. Select the CVSS version tab (v2.0, v3.0, v3.1, v4.0)
2. Click each metric option to set its value
3. The score and severity update automatically
4. Use **Copy Link** to share the exact configuration

### Converter

Convert a CVSS vector string from one version to another. Useful when a vendor publishes a v3.1 score and you need a v4.0 equivalent, or when mapping historical v2.0 scores to modern ratings.

```
Input:  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  (9.8 Critical)
Output: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

> Conversion is a best-effort mapping. Metrics without a direct equivalent are set to their default value. The resulting score may differ from the original.

### AI Scorer

Describe a vulnerability in plain language and let AI assign the CVSS v3.1 metrics. The AI explains its reasoning for each metric choice.

**Example input:**
> "An unauthenticated attacker can send a specially crafted packet to port 443, triggering a heap overflow in the TLS parsing library. Successful exploitation gives the attacker code execution as the web server process."

**AI output:**
- **AV:N** — Exploitable over the network
- **AC:L** — No special conditions required
- **PR:N** — No authentication required
- **UI:N** — No user action needed
- **S:U** — Impact confined to the web server process
- **C:H / I:H / A:H** — Code execution leads to full compromise

Powered by [OpenRouter](https://openrouter.ai/) with configurable model selection.

### CVE Search

Search any CVE identifier to retrieve its official CVSS scores from the **National Vulnerability Database (NVD)**. Results show all available versions (v2.0, v3.0/3.1, v4.0) with their vector strings.

From the results you can:
- **Open in Calculator** — load the vector into the interactive calculator
- **Convert** — send the vector to the Converter
- **Copy** — copy the vector string to clipboard

Results are cached for 24 hours to reduce NVD API load.

### API

Programmatic access to all CVSS Guru functionality. See the [API Reference](/api-reference) for full documentation.

**Quick example:**

```bash
# Calculate a CVSS v3.1 score
curl -X POST https://cvss.guru/api/v1/calculate/3.1 \
  -H "Content-Type: application/json" \
  -d '{"AV":"N","AC":"L","PR":"N","UI":"N","S":"C","C":"H","I":"H","A":"H"}'
```

```json
{
  "version": "3.1",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "scores": {
    "base": { "score": 10.0, "severity": "Critical" },
    "temporal": null,
    "environmental": null
  }
}
```

---

## Interpreting Scores

### CVSS Is Not Risk

A CVSS score measures **exploitability and impact** of a vulnerability in isolation. It does not measure:

- How likely exploitation is in your environment
- Whether public exploit code exists (unless Temporal metrics are included)
- The value of the affected asset
- Whether a compensating control already mitigates the risk

**Example:** A Critical (10.0) vulnerability in a database server exposed to the internet is far more risky than the same vulnerability in a development machine with no network access — even though the CVSS score is identical.

### Prioritization Strategy

A practical tiered approach:

1. **Critical (9.0–10.0):** Patch within 24–72 hours. No exceptions for internet-facing systems.
2. **High (7.0–8.9):** Patch within 2 weeks for production systems.
3. **Medium (4.0–6.9):** Include in next sprint or scheduled maintenance.
4. **Low (0.1–3.9):** Address opportunistically, may accept as residual risk.
5. **None (0.0):** No action required.

### Using Environmental Metrics

Always adjust CVSS scores with Environmental metrics for your context:

```
# A confidentiality-only asset (logs server): C:H doesn't matter much
# Set CR:L (Confidentiality Requirement: Low) to reduce the score

CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
Base Score: 7.5 High

Modified with CR:L:
Environmental Score: 5.3 Medium
```

---

## Real-World Examples

### CVE-2021-44228 — Log4Shell

**What it is:** Remote code execution in Apache Log4j 2.x via JNDI lookup in log messages.

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
Score: 10.0 — Critical
```

Why 10.0: Network-exploitable, no authentication, no user interaction, scope changed (JVM → OS), full CIA impact.

---

### CVE-2022-0847 — Dirty Pipe

**What it is:** Linux kernel privilege escalation via pipe buffer flag overwrite.

```
CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
Score: 7.8 — High
```

Why 7.8: Requires local access (AV:L) and low privileges (PR:L), but leads to full compromise.

---

### CVE-2023-23397 — Microsoft Outlook NTLM Relay

**What it is:** Zero-click NTLM hash theft via specially crafted email reminder.

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Score: 9.8 — Critical
```

Why 9.8 not 10.0: Scope remains Unchanged (S:U), so the score is 9.8 instead of 10.0.

---

### CVE-2021-21985 — VMware vCenter RCE

**What it is:** Remote code execution via vSphere Client without authentication.

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
Score: 9.8 — Critical
```

---

## Resources

- [FIRST.org CVSS Specification](https://www.first.org/cvss/)
- [NVD National Vulnerability Database](https://nvd.nist.gov/)
- [CVSS v3.1 User Guide](https://www.first.org/cvss/user-guide)
- [CVSS v4.0 Specification](https://www.first.org/cvss/v4.0/specification-document)
- [CVSS Guru API Reference](/api-reference)
