# Risk Assessment: OT/ICS Lab — Asset and Network Level

**Type:** Formal risk assessment applying IEC 62443 risk methodology, sequenced from a single critical asset (the PLC) up to the full network architecture. Built as the analytical layer connecting the rest of the portfolio: [ot-purdue-model-mapping](https://github.com/carmelin-neto/ot-purdue-model-mapping) built the architecture, [ics-modbus-attack-testing](https://github.com/carmelin-neto/ics-modbus-attack-testing) proved specific attacks work, [ot-vulnerability-assessment](https://github.com/carmelin-neto/ot-vulnerability-assessment) found what's exposed — this document is where that evidence gets turned into prioritized decisions.
The single-layer-control gap identified in the lateral movement threat here is addressed by [ot-access-control-design](https://github.com/carmelin-neto/ot-access-control-design), which supplies the second defense-in-depth layer.

**Why asset-first, then network:** Risk assessments that start at the network level tend to produce generic findings ("the network should be segmented") that don't tell anyone what to fix first. Starting at the asset and working outward keeps every risk tied to a specific, real consequence before it gets generalized into an architectural recommendation.

**Methodology:** IEC 62443-3-2 risk assessment approach — asset identification, threat identification, vulnerability identification, likelihood and impact scoring, risk calculation, and mitigation mapped to residual risk. Likelihood and Impact are each scored 1–5; Risk = Likelihood × Impact, on a 1–25 scale, bucketed as Low (1–6), Medium (7–14), High (15–25).

---

## Part 1: Asset-Level Risk Assessment

**Asset:** The PLC at `192.168.95.2` in the GRFICS lab, controlling a simulated chemical batch process via Modbus TCP.

**Why this asset first:** It is the single point in the entire lab where a cyber event translates directly into a physical-world consequence. Everything else in this environment — the network segmentation, the DMZ, the IDS — exists to protect this asset or detect threats to it. Any risk assessment that doesn't start here is assessing the wrong thing first.

### Threat 1: Unauthorized Modbus Register Write

**Description:** An attacker on the network path to the PLC sends a Modbus write command (function code 6) to alter a holding register controlling process state — proven not hypothetical, since this exact attack was executed and confirmed successful in [ics-modbus-attack-testing](https://github.com/carmelin-neto/ics-modbus-attack-testing).

**Vulnerability exploited:** Modbus has no built-in authentication (protocol-level design limitation, confirmed exposed via [ot-vulnerability-assessment](https://github.com/carmelin-neto/ot-vulnerability-assessment) — port 502 open, no access control at the application layer).

| Factor | Score | Reasoning |
|---|---|---|
| Likelihood | 4/5 | No authentication barrier at the protocol level; only mitigated by what reaches the segment in the first place. Proven executable with basic tooling (Python/pymodbus). |
| Impact | 5/5 | Direct write access to process control registers — in a real deployment, this is the boundary between a network event and a physical safety incident. |
| **Inherent Risk** | **20/25 — High** | Before any of this portfolio's mitigations are applied |

**Existing mitigations (already built, not hypothetical):**
- Network segmentation restricting which sources can reach port 502 ([ot-purdue-model-mapping](https://github.com/carmelin-neto/ot-purdue-model-mapping))
- Suricata IDS rule detecting this exact write signature, Splunk alert scheduled on it, both validated firing against live triggered traffic ([ics-modbus-attack-testing](https://github.com/carmelin-neto/ics-modbus-attack-testing))
- A documented incident response procedure specifically for this attack pattern ([ot-incident-response-scenario](https://github.com/carmelin-neto/ot-incident-response-scenario))

| Factor | Score | Reasoning |
|---|---|---|
| Residual Likelihood | 2/5 | Segmentation limits who can reach the port; detection means an attempt that does occur is caught quickly |
| Residual Impact | 4/5 | Impact itself is unchanged by these controls — a successful write is still a successful write. Controls reduce likelihood and response time, not the severity of a write that does land. |
| **Residual Risk** | **8/25 — Medium** | Down from High, not eliminated — an honest ceiling given Modbus's own design |

**Why residual risk cannot go lower without changing the protocol itself:** No control in this portfolio changes the fact that Modbus, once reached, accepts writes from anyone. The mitigations reduce *how likely* an attacker is to reach that point and *how fast* a write is caught — they cannot make the write itself safe. A genuinely lower residual score would require either a Modbus security extension (not universally supported by legacy field devices) or removing write capability from the network path entirely, which may not be operationally viable. This ceiling is worth stating plainly rather than implying the risk is fully solved.

### Threat 2: Denial of Service via Exposed Development Server (CVE-2023-46136)

**Description:** The Werkzeug 2.3.7 development server on port 8080 ([ot-vulnerability-assessment](https://github.com/carmelin-neto/ot-vulnerability-assessment)) is vulnerable to a documented DoS via crafted multipart form data.

| Factor | Score | Reasoning |
|---|---|---|
| Likelihood | 3/5 | Publicly documented CVE with known trigger conditions; requires network reachability to port 8080, which is present |
| Impact | 3/5 | DoS against what appears to be an HMI/monitoring interface, not the control path itself — operationally disruptive (loss of visibility) but not a direct process-safety event, based on current understanding of what this service provides |
| **Inherent Risk** | **9/25 — Medium** | |

**Existing mitigation:** None specific to this finding yet — no patch has been applied, and no compensating control (segmentation restricting this port specifically) was confirmed during the vulnerability assessment.

**Residual Risk: 9/25 — Medium (unchanged).** This is the one finding in this portfolio without an existing mitigation, and that gap is deliberately not hidden — a risk assessment that shows every risk already fully mitigated isn't credible. This is exactly the kind of finding that should drive a concrete next action rather than sit acknowledged and unaddressed.

**Recommended action:** Upgrade Werkzeug to 3.0.1+, or, if immediate upgrade isn't feasible, restrict network access to port 8080 to the same trusted sources already permitted to reach the PLC's other management interfaces.

---

## Part 2: Network-Level Risk Assessment

**Scope:** The full segmented architecture from [ot-purdue-model-mapping](https://github.com/carmelin-neto/ot-purdue-model-mapping) — IT zone, DMZ, and OT zone, connected via router-enforced ACLs.

**Why this comes second:** Having established exactly what's at stake at the asset level, the network-level question becomes concrete: does the architecture actually reduce the two risks just quantified, or does it just look like it should on a diagram? This section evaluates the segmentation's real effect rather than assuming a Purdue-Model-shaped diagram automatically implies security.

### Threat 3: Lateral Movement from IT Zone to OT Zone

**Description:** An attacker who compromises a host in the IT zone attempts to reach the OT zone directly, bypassing the DMZ.

| Factor | Score | Reasoning |
|---|---|---|
| Likelihood | 2/5 | Direct IT-to-OT traffic is blocked at the router ACL, confirmed via ping testing in [ot-purdue-model-mapping](https://github.com/carmelin-neto/ot-purdue-model-mapping). Not zero — ACL misconfiguration or a novel bypass technique remains possible, which is why this isn't scored lower. |
| Impact | 5/5 | If achieved, this bypasses every other control in the environment and reaches the PLC directly — same impact ceiling as Threat 1 |
| **Inherent Risk (pre-segmentation)** | **20/25 — High** | What the environment would face with a flat, unsegmented network |
| **Residual Risk (post-segmentation)** | **10/25 — Medium** | Segmentation is doing real, measured work here — this is the single largest risk reduction in the whole assessment |

**This is the clearest evidence in the entire portfolio that the segmentation design isn't just theoretical** — the reduction from 20 to 10 is a direct, testable consequence of the ACL, not an assumption. That said, Medium is not Low: an ACL is a single control, and single controls fail. This finding is the direct justification for why detection (Threat 1's Suricata/Splunk stack) exists as a second layer rather than relying on segmentation alone.

### Threat 4: Network Isolation Assumptions Failing at the Infrastructure Layer

**Description:** During the vulnerability assessment, the attacker-position container's network interface — intended to sit on an isolated lab segment — was found instead bridging directly onto the operator's real physical network via a macvlan configuration, exposing unrelated real-network traffic to what was assumed to be a contained lab environment ([ot-vulnerability-assessment](https://github.com/carmelin-neto/ot-vulnerability-assessment)).

**Why this belongs in a formal risk assessment and not just a scanning-methodology footnote:** This is a genuine example of an *assumed* control (network isolation) not matching the *actual* control (Layer-2 bridging), discovered only through direct testing. This is precisely the category of risk a paper architecture review would miss — the Purdue Model diagram is correct; the underlying infrastructure implementing it had an unreviewed gap.

| Factor | Score | Reasoning |
|---|---|---|
| Likelihood | 3/5 | Specific to macvlan-based isolation choices; would not apply to bridge-network or VLAN-based segmentation using different mechanisms |
| Impact | 2/5 | In this lab context, exposure was to benign home-network traffic, not a security-critical asset — low actual impact here |
| **Risk (this environment)** | **6/25 — Low** | Low specifically because of what happened to be on the other side of the bridge in this lab |

**Why this is flagged as Medium-High in a production-equivalent context despite scoring Low here:** If the network being unintentionally bridged were a corporate network with genuine attack surface, rather than a home lab, Impact would score 4–5, not 2 — pushing this into Medium-to-High territory. The score above reflects this specific lab's actual exposure; the underlying architectural lesson (verify isolation mechanisms match isolation assumptions) generalizes regardless of score.

---

## Risk Summary

| # | Threat | Level | Residual Level | Status |
|---|---|---|---|---|
| 1 | Unauthorized Modbus write | Asset | High → Medium | Mitigated (segmentation + detection); ceiling exists due to protocol design |
| 2 | Werkzeug DoS (CVE-2023-46136) | Asset | Medium (unchanged) | **Unmitigated — action required** |
| 3 | IT-to-OT lateral movement | Network | High → Medium | Mitigated (ACL enforcement); single-layer, hence Threat 1's detection as backup |
| 4 | Isolation assumption failure (macvlan) | Network | Low (this context) | Identified via testing, not architecture review; generalizable lesson |

**Highest-priority open action:** Threat 2 (Werkzeug) is the only finding in this assessment without an existing mitigation. Everything else in this portfolio already has a control attached to it — this is the gap that should be closed next.

## Portfolio Connections

| This assessment | Relationship |
|---|---|
| [ot-purdue-model-mapping](https://github.com/carmelin-neto/ot-purdue-model-mapping) | Source of the network-level architecture being assessed |
| [ics-modbus-attack-testing](https://github.com/carmelin-neto/ics-modbus-attack-testing) | Source of proven impact for Threat 1, and its detection mitigation |
| [ot-vulnerability-assessment](https://github.com/carmelin-neto/ot-vulnerability-assessment) | Source of all vulnerability data feeding this assessment's scoring |
| [ot-incident-response-scenario](https://github.com/carmelin-neto/ot-incident-response-scenario) | The response procedure for Threat 1 if it materializes despite mitigation |
