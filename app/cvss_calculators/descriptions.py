"""
CVSS Metric Descriptions (English), written for non-specialists.

Each metric has:
  name         full metric name
  question     one plain-language line shown under the metric in the calculator
  description  a slightly longer explanation (help dialog)
  values       {key: {label, desc, score?}} — desc is shown when the value is selected

`score` is the weight the v2.0 / v3.x formulas use for that value (shown next to
the option). CVSS v4.0 has no per-metric weights (it uses a lookup table of
"macro vectors"), so v4 values have no score.
Wording follows the FIRST specifications: https://www.first.org/cvss/
"""

CVSS_DESCRIPTIONS = {
    "versions": {
        "2.0": {
            "name": "CVSS v2.0",
            "year": 2007,
            "description": "The first widely used CVSS version. Uses base, temporal, and environmental metrics to calculate vulnerability severity.",
            "score_range": "0.0 - 10.0",
            "formula": "Base + Temporal + Environmental"
        },
        "3.0": {
            "name": "CVSS v3.0",
            "year": 2015,
            "description": "Major update that introduced Scope, User Interaction and Privileges Required.",
            "score_range": "0.0 - 10.0",
            "formula": "Roundup(Roundup(Base) + Roundup(Temporal) + Roundup(Environmental))"
        },
        "3.1": {
            "name": "CVSS v3.1",
            "year": 2019,
            "description": "Same metrics as v3.0 with clearer definitions and a small rounding fix. The most used version today.",
            "score_range": "0.0 - 10.0",
            "formula": "Similar to v3.0 with improved documentation"
        },
        "4.0": {
            "name": "CVSS v4.0",
            "year": 2023,
            "description": "Latest version: new Attack Requirements metric, impact split between the vulnerable and subsequent systems, Threat and Supplemental metrics.",
            "score_range": "0.0 - 10.0",
            "formula": "Lookup table of macro vectors (Base, Threat, Environmental)"
        }
    },

    # ==================== CVSS v2.0 Metrics ====================
    "v2": {
        "base": {
            "AV": {
                "name": "Access Vector",
                "question": "From where can an attacker exploit it?",
                "description": "How close the attacker needs to be to the vulnerable system: the more remote, the higher the score.",
                "values": {
                    "L": {"label": "Local (L)", "score": 0.395, "desc": "The attacker needs physical access or a local account on the machine."},
                    "A": {"label": "Adjacent Network (A)", "score": 0.646, "desc": "The attacker must be on the same local network, e.g. the same Wi-Fi, LAN or Bluetooth range."},
                    "N": {"label": "Network (N)", "score": 1.0, "desc": "Exploitable remotely, e.g. over the Internet. This is the most dangerous case."}
                }
            },
            "AC": {
                "name": "Access Complexity",
                "question": "How hard is the attack to pull off?",
                "description": "Conditions the attacker cannot control that must be in place for the attack to work.",
                "values": {
                    "H": {"label": "High (H)", "score": 0.35, "desc": "Needs special, rare conditions (e.g. winning a race condition or tricking a specific user)."},
                    "M": {"label": "Medium (M)", "score": 0.61, "desc": "Needs some specific conditions, such as a non-default configuration or a group of targets."},
                    "L": {"label": "Low (L)", "score": 0.71, "desc": "No special conditions: the attack works reliably, whenever the attacker wants."}
                }
            },
            "Au": {
                "name": "Authentication",
                "question": "Does the attacker have to log in first?",
                "description": "How many times the attacker must authenticate to the target before exploiting the vulnerability.",
                "values": {
                    "M": {"label": "Multiple (M)", "score": 0.45, "desc": "The attacker has to log in twice or more, even with the same credentials."},
                    "S": {"label": "Single (S)", "score": 0.56, "desc": "The attacker needs to log in once (e.g. a normal user account)."},
                    "N": {"label": "None (N)", "score": 0.704, "desc": "No login needed: anyone who can reach the system can attack it."}
                }
            },
            "C": {
                "name": "Confidentiality Impact",
                "question": "Can the attacker read data they shouldn't?",
                "description": "How much information the attacker can access once the vulnerability is exploited.",
                "values": {
                    "N": {"label": "None (N)", "score": 0.0, "desc": "No information is disclosed."},
                    "P": {"label": "Partial (P)", "score": 0.275, "desc": "Some information can be read, but the attacker can't choose what or get everything."},
                    "C": {"label": "Complete (C)", "score": 0.660, "desc": "All data on the system can be read."}
                }
            },
            "I": {
                "name": "Integrity Impact",
                "question": "Can the attacker change or delete data?",
                "description": "How much the attacker can modify files, data or system settings.",
                "values": {
                    "N": {"label": "None (N)", "score": 0.0, "desc": "Nothing can be modified."},
                    "P": {"label": "Partial (P)", "score": 0.275, "desc": "Some files or data can be modified, with limited control."},
                    "C": {"label": "Complete (C)", "score": 0.660, "desc": "The attacker can modify anything on the system."}
                }
            },
            "A": {
                "name": "Availability Impact",
                "question": "Can the attacker slow down or stop the system?",
                "description": "How much the attack can disrupt access to the system or service.",
                "values": {
                    "N": {"label": "None (N)", "score": 0.0, "desc": "The system keeps working normally."},
                    "P": {"label": "Partial (P)", "score": 0.275, "desc": "Slowdowns or interruptions, but the system stays partly usable."},
                    "C": {"label": "Complete (C)", "score": 0.660, "desc": "The system can be shut down completely."}
                }
            }
        },
        "temporal": {
            "E": {
                "name": "Exploitability",
                "question": "Is there working attack code out there?",
                "description": "How mature the available exploit techniques or code are. It changes over time.",
                "values": {
                    "U": {"label": "Unproven (U)", "score": 0.85, "desc": "No exploit code is known; the attack is only theoretical."},
                    "POC": {"label": "Proof of Concept (POC)", "score": 0.9, "desc": "A demonstration exists, but it's not practical for most systems."},
                    "F": {"label": "Functional (F)", "score": 0.95, "desc": "Working exploit code exists and works in most situations."},
                    "H": {"label": "High (H)", "score": 1.0, "desc": "Reliable, possibly automated exploits exist (e.g. worms or public tools)."},
                    "ND": {"label": "Not Defined (ND)", "score": 1.0, "desc": "Not evaluated: the score is not adjusted."}
                }
            },
            "RL": {
                "name": "Remediation Level",
                "question": "Is a fix available?",
                "description": "Whether a patch or workaround exists. The better the fix, the lower the score.",
                "values": {
                    "OF": {"label": "Official Fix (OF)", "score": 0.87, "desc": "The vendor has released an official patch or upgrade."},
                    "TF": {"label": "Temporary Fix (TF)", "score": 0.90, "desc": "The vendor offers a temporary fix or hotfix."},
                    "W": {"label": "Workaround (W)", "score": 0.95, "desc": "Only an unofficial workaround exists (e.g. from users or third parties)."},
                    "U": {"label": "Unavailable (U)", "score": 1.0, "desc": "No fix of any kind is available yet."},
                    "ND": {"label": "Not Defined (ND)", "score": 1.0, "desc": "Not evaluated: the score is not adjusted."}
                }
            },
            "RC": {
                "name": "Report Confidence",
                "question": "How sure are we that the vulnerability is real?",
                "description": "How confirmed and detailed the reports about the vulnerability are.",
                "values": {
                    "UC": {"label": "Unconfirmed (UC)", "score": 0.90, "desc": "A single unconfirmed source or rumour."},
                    "UR": {"label": "Uncorroborated (UR)", "score": 0.95, "desc": "Several sources, but the details differ or aren't confirmed."},
                    "C": {"label": "Confirmed (C)", "score": 1.0, "desc": "Confirmed by the vendor or reproduced independently."},
                    "ND": {"label": "Not Defined (ND)", "score": 1.0, "desc": "Not evaluated: the score is not adjusted."}
                }
            }
        },
        "environmental": {
            "CDP": {
                "name": "Collateral Damage Potential",
                "question": "How much damage could an attack cause to your organisation?",
                "description": "Potential loss of life, physical assets, productivity or revenue in your environment.",
                "values": {
                    "N": {"label": "None (N)", "score": 0.0, "desc": "No damage beyond the vulnerable system."},
                    "L": {"label": "Low (L)", "score": 0.1, "desc": "Slight damage or minor loss of revenue or productivity."},
                    "LM": {"label": "Low-Medium (LM)", "score": 0.3, "desc": "Moderate damage or loss."},
                    "MH": {"label": "Medium-High (MH)", "score": 0.4, "desc": "Significant damage or loss."},
                    "H": {"label": "High (H)", "score": 0.5, "desc": "Catastrophic damage, possibly including physical harm."},
                    "ND": {"label": "Not Defined (ND)", "score": 0.0, "desc": "Not evaluated: the score is not adjusted."}
                }
            },
            "TD": {
                "name": "Target Distribution",
                "question": "How many of your systems are affected?",
                "description": "The share of systems in your environment that have the vulnerability.",
                "values": {
                    "N": {"label": "None (N)", "score": 0.0, "desc": "None of your systems are affected (or only in a lab)."},
                    "L": {"label": "Low (L)", "score": 0.25, "desc": "Up to 25% of your systems are affected."},
                    "M": {"label": "Medium (M)", "score": 0.75, "desc": "Between 26% and 75% of your systems are affected."},
                    "H": {"label": "High (H)", "score": 1.0, "desc": "More than 75% of your systems are affected."},
                    "ND": {"label": "Not Defined (ND)", "score": 1.0, "desc": "Not evaluated: the score is not adjusted."}
                }
            },
            "CR": {
                "name": "Confidentiality Requirement",
                "question": "How important is keeping this system's data secret for you?",
                "description": "Weights the confidentiality impact by how much secrecy matters in your organisation.",
                "values": {
                    "L": {"label": "Low (L)", "score": 0.5, "desc": "A data leak would have only a limited effect."},
                    "M": {"label": "Medium (M)", "score": 1.0, "desc": "A data leak would have a serious effect."},
                    "H": {"label": "High (H)", "score": 1.51, "desc": "A data leak would be catastrophic."},
                    "ND": {"label": "Not Defined (ND)", "score": 1.0, "desc": "Not evaluated: treated as Medium."}
                }
            },
            "IR": {
                "name": "Integrity Requirement",
                "question": "How important is it that this system's data stays correct?",
                "description": "Weights the integrity impact by how much data accuracy matters in your organisation.",
                "values": {
                    "L": {"label": "Low (L)", "score": 0.5, "desc": "Tampered data would have only a limited effect."},
                    "M": {"label": "Medium (M)", "score": 1.0, "desc": "Tampered data would have a serious effect."},
                    "H": {"label": "High (H)", "score": 1.51, "desc": "Tampered data would be catastrophic."},
                    "ND": {"label": "Not Defined (ND)", "score": 1.0, "desc": "Not evaluated: treated as Medium."}
                }
            },
            "AR": {
                "name": "Availability Requirement",
                "question": "How important is it that this system stays up?",
                "description": "Weights the availability impact by how much uptime matters in your organisation.",
                "values": {
                    "L": {"label": "Low (L)", "score": 0.5, "desc": "Downtime would have only a limited effect."},
                    "M": {"label": "Medium (M)", "score": 1.0, "desc": "Downtime would have a serious effect."},
                    "H": {"label": "High (H)", "score": 1.51, "desc": "Downtime would be catastrophic."},
                    "ND": {"label": "Not Defined (ND)", "score": 1.0, "desc": "Not evaluated: treated as Medium."}
                }
            }
        }
    },

    # ==================== CVSS v3.x Metrics ====================
    "v3": {
        "base": {
            "AV": {
                "name": "Attack Vector",
                "question": "From where can an attacker exploit it?",
                "description": "How close the attacker needs to be to the vulnerable system: the more remote, the higher the score.",
                "values": {
                    "N": {"label": "Network (N)", "score": 0.85, "desc": "Exploitable remotely, e.g. over the Internet. This is the most dangerous case."},
                    "A": {"label": "Adjacent (A)", "score": 0.62, "desc": "The attacker must be on the same local network, e.g. the same Wi-Fi, LAN or Bluetooth range."},
                    "L": {"label": "Local (L)", "score": 0.55, "desc": "The attacker needs to be on the machine (a local account), or trick a user into opening a malicious file."},
                    "P": {"label": "Physical (P)", "score": 0.20, "desc": "The attacker must physically touch the device, e.g. plug in a USB stick."}
                }
            },
            "AC": {
                "name": "Attack Complexity",
                "question": "Does the attack depend on conditions outside the attacker's control?",
                "description": "Whether the attack works every time, or only if something outside the attacker's control happens.",
                "values": {
                    "L": {"label": "Low (L)", "score": 0.77, "desc": "No special conditions: the attack works reliably, whenever the attacker wants."},
                    "H": {"label": "High (H)", "score": 0.44, "desc": "Success depends on things the attacker can't control, e.g. winning a race condition or gathering information about the target first."}
                }
            },
            "PR": {
                "name": "Privileges Required",
                "question": "Does the attacker need an account on the system first?",
                "description": "The level of access the attacker must already have before exploiting the vulnerability.",
                "values": {
                    "N": {"label": "None (N)", "score": 0.85, "desc": "No account needed: anyone who can reach the system can attack it."},
                    "L": {"label": "Low (L)", "score": 0.62, "desc": "A normal user account is enough."},
                    "H": {"label": "High (H)", "score": 0.27, "desc": "Administrator-level access is needed first."}
                }
            },
            "UI": {
                "name": "User Interaction",
                "question": "Does someone other than the attacker have to do something?",
                "description": "Whether a user must take part, e.g. by clicking a link or opening a file, for the attack to succeed.",
                "values": {
                    "N": {"label": "None (N)", "score": 0.85, "desc": "No victim action needed: the attacker can do it all alone."},
                    "R": {"label": "Required (R)", "score": 0.62, "desc": "A user must do something, e.g. click a link, open a file or install something."}
                }
            },
            "S": {
                "name": "Scope",
                "question": "Can the attack spread beyond the vulnerable component?",
                "description": "Whether exploiting the vulnerability lets the attacker affect other components with different security controls, e.g. escaping a sandbox or a virtual machine.",
                "values": {
                    "U": {"label": "Unchanged (U)", "score": None, "desc": "Only the vulnerable component itself (and what it manages) is affected."},
                    "C": {"label": "Changed (C)", "score": None, "desc": "Other components are affected too, e.g. a browser flaw that escapes the sandbox and reaches the operating system."}
                }
            },
            "C": {
                "name": "Confidentiality Impact",
                "question": "Can the attacker read data they shouldn't?",
                "description": "How much information the attacker can access once the vulnerability is exploited.",
                "values": {
                    "N": {"label": "None (N)", "score": 0.0, "desc": "No information is disclosed."},
                    "L": {"label": "Low (L)", "score": 0.22, "desc": "Some data can be read, but the attacker has no control over what, or it's not serious."},
                    "H": {"label": "High (H)", "score": 0.56, "desc": "All data can be read, or some very sensitive data (e.g. passwords or private keys)."}
                }
            },
            "I": {
                "name": "Integrity Impact",
                "question": "Can the attacker change or delete data?",
                "description": "How much the attacker can modify files, data or system settings.",
                "values": {
                    "N": {"label": "None (N)", "score": 0.0, "desc": "Nothing can be modified."},
                    "L": {"label": "Low (L)", "score": 0.22, "desc": "Some data can be modified, with limited control and no serious consequences."},
                    "H": {"label": "High (H)", "score": 0.56, "desc": "The attacker can modify any data, or data with serious consequences."}
                }
            },
            "A": {
                "name": "Availability Impact",
                "question": "Can the attacker slow down or stop the system?",
                "description": "How much the attack can disrupt access to the system or service.",
                "values": {
                    "N": {"label": "None (N)", "score": 0.0, "desc": "The system keeps working normally."},
                    "L": {"label": "Low (L)", "score": 0.22, "desc": "Slowdowns or interruptions, but the service is not fully denied."},
                    "H": {"label": "High (H)", "score": 0.56, "desc": "The attacker can make the system or service completely unavailable."}
                }
            }
        },
        "temporal": {
            "E": {
                "name": "Exploit Code Maturity",
                "question": "Is there working attack code out there?",
                "description": "How mature the available exploit code is. It changes over time, so re-check it later.",
                "values": {
                    "X": {"label": "Not Defined (X)", "score": 1.0, "desc": "Not evaluated: the score is not adjusted (same as High)."},
                    "U": {"label": "Unproven (U)", "score": 0.91, "desc": "No exploit code is known; the attack is only theoretical."},
                    "P": {"label": "Proof of Concept (P)", "score": 0.94, "desc": "A demonstration exists, but it's not practical for most systems."},
                    "F": {"label": "Functional (F)", "score": 0.97, "desc": "Working exploit code exists and works in most situations."},
                    "H": {"label": "High (H)", "score": 1.0, "desc": "Reliable, possibly automated exploits exist or attacks are seen in the wild."}
                }
            },
            "RL": {
                "name": "Remediation Level",
                "question": "Is a fix available?",
                "description": "Whether a patch or workaround exists. The better the fix, the lower the score.",
                "values": {
                    "X": {"label": "Not Defined (X)", "score": 1.0, "desc": "Not evaluated: the score is not adjusted."},
                    "O": {"label": "Official Fix (O)", "score": 0.95, "desc": "The vendor has released an official patch or upgrade."},
                    "T": {"label": "Temporary Fix (T)", "score": 0.96, "desc": "The vendor offers a temporary fix or hotfix."},
                    "W": {"label": "Workaround (W)", "score": 0.97, "desc": "Only an unofficial workaround exists (e.g. from users or third parties)."},
                    "U": {"label": "Unavailable (U)", "score": 1.0, "desc": "No fix of any kind is available yet."}
                }
            },
            "RC": {
                "name": "Report Confidence",
                "question": "How sure are we that the vulnerability is real?",
                "description": "How confirmed and detailed the reports about the vulnerability are.",
                "values": {
                    "X": {"label": "Not Defined (X)", "score": 1.0, "desc": "Not evaluated: the score is not adjusted."},
                    "U": {"label": "Unknown (U)", "score": 0.92, "desc": "Reports exist but the cause is unclear or the reports disagree."},
                    "R": {"label": "Reasonable (R)", "score": 0.96, "desc": "Significant details are published and credible, but not fully confirmed."},
                    "C": {"label": "Confirmed (C)", "score": 1.0, "desc": "Confirmed by the vendor, by source code, or reproduced independently."}
                }
            }
        },
        "environmental": {
            "CR": {
                "name": "Confidentiality Requirement",
                "question": "How important is keeping this system's data secret for you?",
                "description": "Weights the confidentiality impact by how much secrecy matters in your organisation.",
                "values": {
                    "X": {"label": "Not Defined (X)", "score": 1.0, "desc": "Not evaluated: treated as Medium."},
                    "L": {"label": "Low (L)", "score": 0.5, "desc": "A data leak would have only a limited effect."},
                    "M": {"label": "Medium (M)", "score": 1.0, "desc": "A data leak would have a serious effect."},
                    "H": {"label": "High (H)", "score": 1.5, "desc": "A data leak would be catastrophic."}
                }
            },
            "IR": {
                "name": "Integrity Requirement",
                "question": "How important is it that this system's data stays correct?",
                "description": "Weights the integrity impact by how much data accuracy matters in your organisation.",
                "values": {
                    "X": {"label": "Not Defined (X)", "score": 1.0, "desc": "Not evaluated: treated as Medium."},
                    "L": {"label": "Low (L)", "score": 0.5, "desc": "Tampered data would have only a limited effect."},
                    "M": {"label": "Medium (M)", "score": 1.0, "desc": "Tampered data would have a serious effect."},
                    "H": {"label": "High (H)", "score": 1.5, "desc": "Tampered data would be catastrophic."}
                }
            },
            "AR": {
                "name": "Availability Requirement",
                "question": "How important is it that this system stays up?",
                "description": "Weights the availability impact by how much uptime matters in your organisation.",
                "values": {
                    "X": {"label": "Not Defined (X)", "score": 1.0, "desc": "Not evaluated: treated as Medium."},
                    "L": {"label": "Low (L)", "score": 0.5, "desc": "Downtime would have only a limited effect."},
                    "M": {"label": "Medium (M)", "score": 1.0, "desc": "Downtime would have a serious effect."},
                    "H": {"label": "High (H)", "score": 1.5, "desc": "Downtime would be catastrophic."}
                }
            }
        }
    },

    # ==================== CVSS v4.0 Metrics ====================
    # No per-value scores: v4.0 scores whole vectors with a lookup table.
    "v4": {
        "base": {
            "AV": {
                "name": "Attack Vector",
                "question": "From where can an attacker exploit it?",
                "description": "How close the attacker needs to be to the vulnerable system: the more remote, the higher the score.",
                "values": {
                    "N": {"label": "Network (N)", "desc": "Exploitable remotely, e.g. over the Internet. This is the most dangerous case."},
                    "A": {"label": "Adjacent (A)", "desc": "The attacker must be on the same local network, e.g. the same Wi-Fi, LAN or Bluetooth range."},
                    "L": {"label": "Local (L)", "desc": "The attacker needs to be on the machine (a local account), or trick a user into opening a malicious file."},
                    "P": {"label": "Physical (P)", "desc": "The attacker must physically touch the device, e.g. plug in a USB stick."}
                }
            },
            "AC": {
                "name": "Attack Complexity",
                "question": "Does the attacker have to defeat security protections?",
                "description": "Whether the attacker must bypass built-in defences (such as address randomisation) or obtain secrets like keys to succeed.",
                "values": {
                    "L": {"label": "Low (L)", "desc": "No protections to work around: the attack works reliably."},
                    "H": {"label": "High (H)", "desc": "The attacker must bypass active protections or obtain target-specific secrets first."}
                }
            },
            "AT": {
                "name": "Attack Requirements",
                "question": "Does the attack only work in particular situations?",
                "description": "Conditions of the target's deployment or execution that must be present, independent of the attacker's skill (new in v4.0).",
                "values": {
                    "N": {"label": "None (N)", "desc": "Works on any vulnerable system, regardless of how it is set up."},
                    "P": {"label": "Present (P)", "desc": "Needs specific conditions, e.g. a race condition, a particular configuration, or the attacker in the network path."}
                }
            },
            "PR": {
                "name": "Privileges Required",
                "question": "Does the attacker need an account on the system first?",
                "description": "The level of access the attacker must already have before exploiting the vulnerability.",
                "values": {
                    "N": {"label": "None (N)", "desc": "No account needed: anyone who can reach the system can attack it."},
                    "L": {"label": "Low (L)", "desc": "A normal user account is enough."},
                    "H": {"label": "High (H)", "desc": "Administrator-level access is needed first."}
                }
            },
            "UI": {
                "name": "User Interaction",
                "question": "Does someone other than the attacker have to do something?",
                "description": "Whether a user must take part for the attack to succeed, and how actively.",
                "values": {
                    "N": {"label": "None (N)", "desc": "No victim action needed: the attacker can do it all alone."},
                    "P": {"label": "Passive (P)", "desc": "A user only has to do something ordinary, like visiting a web page or viewing a message."},
                    "A": {"label": "Active (A)", "desc": "A user must deliberately do something, e.g. install a file, change a setting or ignore a warning."}
                }
            },
            "VC": {
                "name": "Confidentiality Impact to Vulnerable System",
                "question": "Can the attacker read data on the vulnerable system?",
                "description": "Information the attacker can access on the system that has the vulnerability.",
                "values": {
                    "N": {"label": "None (N)", "desc": "No information is disclosed."},
                    "L": {"label": "Low (L)", "desc": "Some data can be read, but the attacker has no control over what, or it's not serious."},
                    "H": {"label": "High (H)", "desc": "All data can be read, or some very sensitive data (e.g. passwords or private keys)."}
                }
            },
            "VI": {
                "name": "Integrity Impact to Vulnerable System",
                "question": "Can the attacker change data on the vulnerable system?",
                "description": "How much the attacker can modify files, data or settings on the system that has the vulnerability.",
                "values": {
                    "N": {"label": "None (N)", "desc": "Nothing can be modified."},
                    "L": {"label": "Low (L)", "desc": "Some data can be modified, with limited control and no serious consequences."},
                    "H": {"label": "High (H)", "desc": "The attacker can modify any data, or data with serious consequences."}
                }
            },
            "VA": {
                "name": "Availability Impact to Vulnerable System",
                "question": "Can the attacker slow down or stop the vulnerable system?",
                "description": "How much the attack can disrupt the system that has the vulnerability.",
                "values": {
                    "N": {"label": "None (N)", "desc": "The system keeps working normally."},
                    "L": {"label": "Low (L)", "desc": "Slowdowns or interruptions, but the service is not fully denied."},
                    "H": {"label": "High (H)", "desc": "The attacker can make the system completely unavailable."}
                }
            },
            "SC": {
                "name": "Confidentiality Impact to Subsequent Systems",
                "question": "Can the attack expose data on other systems too?",
                "description": "Impact on systems beyond the vulnerable one, e.g. other services reached from it (new in v4.0).",
                "values": {
                    "N": {"label": "None (N)", "desc": "No other systems are affected."},
                    "L": {"label": "Low (L)", "desc": "Some data on other systems can be read, with limited control."},
                    "H": {"label": "High (H)", "desc": "All data, or very sensitive data, on other systems can be read."}
                }
            },
            "SI": {
                "name": "Integrity Impact to Subsequent Systems",
                "question": "Can the attack change data on other systems too?",
                "description": "Impact on systems beyond the vulnerable one, e.g. other services reached from it (new in v4.0).",
                "values": {
                    "N": {"label": "None (N)", "desc": "No other systems are affected."},
                    "L": {"label": "Low (L)", "desc": "Some data on other systems can be modified, with limited control."},
                    "H": {"label": "High (H)", "desc": "Any data on other systems can be modified, with serious consequences."}
                }
            },
            "SA": {
                "name": "Availability Impact to Subsequent Systems",
                "question": "Can the attack take other systems down too?",
                "description": "Impact on systems beyond the vulnerable one, e.g. other services reached from it (new in v4.0).",
                "values": {
                    "N": {"label": "None (N)", "desc": "No other systems are affected."},
                    "L": {"label": "Low (L)", "desc": "Other systems slow down or are partly interrupted."},
                    "H": {"label": "High (H)", "desc": "Other systems can be made completely unavailable."}
                }
            }
        },
        "threat": {
            "E": {
                "name": "Exploit Maturity",
                "question": "Is this vulnerability being attacked, or is attack code public?",
                "description": "How likely the vulnerability is to be attacked, based on known exploits and attacks. Re-check it over time.",
                "values": {
                    "X": {"label": "Not Defined (X)", "desc": "Not evaluated: assumed to be the worst case (Attacked)."},
                    "A": {"label": "Attacked (A)", "desc": "Attacks have been reported, or easy-to-use exploit tools are available."},
                    "P": {"label": "Proof of Concept (P)", "desc": "Demonstration code is public, but no attacks are known."},
                    "U": {"label": "Unreported (U)", "desc": "No public exploit code and no known attacks."}
                }
            }
        },
        "environmental": {
            "CR": {
                "name": "Confidentiality Requirement",
                "question": "How important is keeping this system's data secret for you?",
                "description": "Weights the confidentiality impact by how much secrecy matters in your organisation.",
                "values": {
                    "X": {"label": "Not Defined (X)", "desc": "Not evaluated: treated as High (worst case)."},
                    "L": {"label": "Low (L)", "desc": "A data leak would have only a limited effect."},
                    "M": {"label": "Medium (M)", "desc": "A data leak would have a serious effect."},
                    "H": {"label": "High (H)", "desc": "A data leak would be catastrophic."}
                }
            },
            "IR": {
                "name": "Integrity Requirement",
                "question": "How important is it that this system's data stays correct?",
                "description": "Weights the integrity impact by how much data accuracy matters in your organisation.",
                "values": {
                    "X": {"label": "Not Defined (X)", "desc": "Not evaluated: treated as High (worst case)."},
                    "L": {"label": "Low (L)", "desc": "Tampered data would have only a limited effect."},
                    "M": {"label": "Medium (M)", "desc": "Tampered data would have a serious effect."},
                    "H": {"label": "High (H)", "desc": "Tampered data would be catastrophic."}
                }
            },
            "AR": {
                "name": "Availability Requirement",
                "question": "How important is it that this system stays up?",
                "description": "Weights the availability impact by how much uptime matters in your organisation.",
                "values": {
                    "X": {"label": "Not Defined (X)", "desc": "Not evaluated: treated as High (worst case)."},
                    "L": {"label": "Low (L)", "desc": "Downtime would have only a limited effect."},
                    "M": {"label": "Medium (M)", "desc": "Downtime would have a serious effect."},
                    "H": {"label": "High (H)", "desc": "Downtime would be catastrophic."}
                }
            },
            # Modified Subsequent System impact: MSI/MSA also allow "Safety"
            "MSC": {
                "name": "Modified Confidentiality (Subsequent)",
                "question": "Is the impact on other systems' data secrecy different in your environment?",
                "description": "Overrides the base Subsequent System Confidentiality value for your environment.",
                "values": {
                    "X": {"label": "Not Defined (X)", "desc": "Keep the base value."},
                    "N": {"label": "Negligible (N)", "desc": "No meaningful impact on other systems in your environment."},
                    "L": {"label": "Low (L)", "desc": "Some data on other systems can be read, with limited control."},
                    "H": {"label": "High (H)", "desc": "All data, or very sensitive data, on other systems can be read."}
                }
            },
            "MSI": {
                "name": "Modified Integrity (Subsequent)",
                "question": "Is the impact on other systems' data different in your environment?",
                "description": "Overrides the base Subsequent System Integrity value. \"Safety\" means the attack could hurt people.",
                "values": {
                    "X": {"label": "Not Defined (X)", "desc": "Keep the base value."},
                    "N": {"label": "Negligible (N)", "desc": "No meaningful impact on other systems in your environment."},
                    "L": {"label": "Low (L)", "desc": "Some data on other systems can be modified, with limited control."},
                    "H": {"label": "High (H)", "desc": "Any data on other systems can be modified, with serious consequences."},
                    "S": {"label": "Safety (S)", "desc": "Tampering could cause physical harm to people (e.g. medical or industrial devices)."}
                }
            },
            "MSA": {
                "name": "Modified Availability (Subsequent)",
                "question": "Is the impact on other systems' uptime different in your environment?",
                "description": "Overrides the base Subsequent System Availability value. \"Safety\" means the attack could hurt people.",
                "values": {
                    "X": {"label": "Not Defined (X)", "desc": "Keep the base value."},
                    "N": {"label": "Negligible (N)", "desc": "No meaningful impact on other systems in your environment."},
                    "L": {"label": "Low (L)", "desc": "Other systems slow down or are partly interrupted."},
                    "H": {"label": "High (H)", "desc": "Other systems can be made completely unavailable."},
                    "S": {"label": "Safety (S)", "desc": "An outage could cause physical harm to people (e.g. medical or industrial devices)."}
                }
            }
        },
        "supplemental": {
            "S": {
                "name": "Safety",
                "question": "Could exploiting it put people's physical safety at risk?",
                "description": "Extra information only: it does not change the score.",
                "values": {
                    "X": {"label": "Not Defined (X)", "desc": "Not evaluated."},
                    "N": {"label": "Negligible (N)", "desc": "No meaningful risk of injury."},
                    "P": {"label": "Present (P)", "desc": "Could lead to injury, e.g. in medical, industrial or automotive systems."}
                }
            },
            "AU": {
                "name": "Automatable",
                "question": "Could the attack be automated at scale?",
                "description": "Whether an attacker could automate the whole attack across many targets (e.g. a worm). Extra information only: it does not change the score.",
                "values": {
                    "X": {"label": "Not Defined (X)", "desc": "Not evaluated."},
                    "N": {"label": "No (N)", "desc": "At least one step can't be reliably automated."},
                    "Y": {"label": "Yes (Y)", "desc": "Every step can be automated, so it could spread to many systems quickly."}
                }
            },
            "R": {
                "name": "Recovery",
                "question": "How easily does the system recover after an attack?",
                "description": "Extra information only: it does not change the score.",
                "values": {
                    "X": {"label": "Not Defined (X)", "desc": "Not evaluated."},
                    "A": {"label": "Automatic (A)", "desc": "The system recovers by itself."},
                    "U": {"label": "User (U)", "desc": "Someone has to step in to restore it."},
                    "I": {"label": "Irrecoverable (I)", "desc": "The system can't be recovered."}
                }
            },
            "V": {
                "name": "Value Density",
                "question": "How much does an attacker gain with a single successful attack?",
                "description": "Extra information only: it does not change the score.",
                "values": {
                    "X": {"label": "Not Defined (X)", "desc": "Not evaluated."},
                    "D": {"label": "Diffuse (D)", "desc": "Limited resources per target, e.g. a single user's device."},
                    "C": {"label": "Concentrated (C)", "desc": "Rich resources in one place, e.g. a central server or database."}
                }
            },
            "RE": {
                "name": "Vulnerability Response Effort",
                "question": "How hard is it for you to respond to it?",
                "description": "Effort needed to mitigate or fix the vulnerability once known. Extra information only: it does not change the score.",
                "values": {
                    "X": {"label": "Not Defined (X)", "desc": "Not evaluated."},
                    "L": {"label": "Low (L)", "desc": "Little effort, e.g. a simple configuration change or an easy update."},
                    "M": {"label": "Moderate (M)", "desc": "Some effort, e.g. a planned update with a short service interruption."},
                    "H": {"label": "High (H)", "desc": "Significant effort, e.g. hardware replacement or long downtime."}
                }
            },
            "U": {
                "name": "Provider Urgency",
                "question": "How urgent does the vendor say it is?",
                "description": "The vendor's own assessment of urgency. Extra information only: it does not change the score.",
                "values": {
                    "X": {"label": "Not Defined (X)", "desc": "Not evaluated."},
                    "Clear": {"label": "Clear", "desc": "Informational only, or very low impact."},
                    "Green": {"label": "Green", "desc": "Reduced urgency."},
                    "Amber": {"label": "Amber", "desc": "Moderate urgency."},
                    "Red": {"label": "Red", "desc": "Highest urgency."}
                }
            }
        }
    },

    # ==================== Severity Ratings ====================
    "severity": {
        "none": {"label": "None", "range": "0.0", "color": "#808080", "desc": "No vulnerability"},
        "low": {"label": "Low", "range": "0.1 - 3.9", "color": "#ffcc00", "desc": "Low risk, difficult to exploit or limited impact"},
        "medium": {"label": "Medium", "range": "4.0 - 6.9", "color": "#ff9900", "desc": "Moderate risk, requires some conditions"},
        "high": {"label": "High", "range": "7.0 - 8.9", "color": "#ff6600", "desc": "High risk, easy to exploit or significant impact"},
        "critical": {"label": "Critical", "range": "9.0 - 10.0", "color": "#cc0000", "desc": "Critical risk, immediate action required"}
    }
}
