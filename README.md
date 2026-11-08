# NetSage AI – AI-Assisted Network Troubleshooting

An AI-assisted network troubleshooting project developed as part of the **Cisco-AICTE Virtual Internship Program 2026 (AI Track)**.

NetSage AI combines AI-assisted diagnosis, human review, deterministic Python-based rule verification, Cisco Packet Tracer validation, and Excel-based analysis to investigate common network configuration problems.

## Project Overview

Network troubleshooting often requires analyzing device configurations, command-line outputs, network topology, and connectivity symptoms.

NetSage AI provides a structured workflow to identify possible root causes, review AI-generated diagnoses, validate network evidence, and document the results.

**Project Workflow:**

Diagnose → Review → Fix → Verify

## Key Features

- AI-assisted diagnosis using structured network troubleshooting prompts.
- Analysis of 30 network troubleshooting cases.
- Coverage of eight network issue categories.
- Human review of AI outputs: Accepted, Edited, and Rejected.
- Python-based deterministic rule verification.
- Cisco Packet Tracer VLAN troubleshooting demonstration.
- Excel dashboard for issue distribution, severity analysis, and AI vs. human review.

## Network Issues Covered

| Category | Number of Cases |
|---|---:|
| VLAN | 4 |
| Routing | 8 |
| DHCP | 4 |
| DNS | 2 |
| ACL | 5 |
| NAT | 3 |
| Wireless | 3 |
| Gateway | 1 |
| **Total** | **30** |

## Python Rule Checker

The project includes a Python-based deterministic rule checker that independently evaluates network evidence.

It implements six verification checks:

1. Duplicate IP Addresses
2. Subnet Mask Mismatch
3. Default Gateway Mismatch
4. Interface Status Down
5. Missing VLAN Configuration
6. Missing Route

The checker uses predefined rules and does not depend on AI-generated answers. Missing evidence is reported as `NOT_CHECKED` instead of automatically treating it as a failure.

## Human Review Results

The 30 cases were reviewed and categorized as:

| Review Status | Cases |
|---|---:|
| Accepted | 16 |
| Edited | 8 |
| Rejected | 6 |

## Severity Analysis

| Severity | Cases |
|---|---:|
| Critical | 7 |
| High | 14 |
| Medium | 9 |

## Cisco Packet Tracer Demonstration

The project includes a VLAN mismatch troubleshooting demonstration.

- PC0 and PC1 initially could not communicate.
- Switch verification identified Fa0/2 in VLAN 10 and Fa0/3 in VLAN 20.
- Fa0/3 was assigned to VLAN 10.
- Connectivity was verified successfully using ping with 0% packet loss.

## Technologies and Tools

- Python
- Cisco Packet Tracer
- Microsoft Excel
- CSV
- AI Prompt Engineering
- Markdown

## Project Structure

```text
NetSage-AI-Network-Troubleshooting/
│
├── dashboard/
├── data/
├── demo/
├── documentation/
├── packet-tracer/
├── python/
└── results/
```

## Running the Python Rule Checker

**Requirements:** Python 3.9 or later.

The rule checker uses Python's standard library.

Clone the repository:

```bash
git clone https://github.com/ZeelBhakhar/NetSage-AI-Network-Troubleshooting.git
```

Navigate to the repository:

```bash
cd NetSage-AI-Network-Troubleshooting
```

Run the checker:

```bash
python python/rule_checker.py --csv data/cases.csv --output results/rule_checker_results.csv
```

The generated results will be saved in the `results/` directory.

## My Contribution

My individual contributions to this project included:

- Implementing the VLAN troubleshooting demonstration using Cisco Packet Tracer.
- Preparing the Excel dashboard and project analysis.
- Developing and testing the Python rule checker with AI assistance.
- Recording the project demonstration video.
- Reviewing project outputs and documenting the workflow.

## Internship

**Cisco-AICTE Virtual Internship Program 2026 – AI Track**

This project was completed as part of the internship's project work.

## Conclusion

NetSage AI demonstrates how AI-assisted diagnosis can be combined with human judgment, deterministic rule-based verification, and network simulation to support structured network troubleshooting.

The project highlights the importance of evidence-based diagnosis and independent verification rather than relying entirely on AI-generated results.

---

**Developed by:** Zeel Bhakhar

**GitHub:** [ZeelBhakhar](https://github.com/ZeelBhakhar)
