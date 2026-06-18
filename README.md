# Cloud Resilience Visualizer

A Cloud Security Posture Management (CSPM) learning project — visualises AWS configurations on a logical topology and maps misconfigurations to NIS2, NCSC CAF 4.0, and MITRE ATT&CK.

> Portfolio / learning project. Not a commercial Cloud Security Posture Management (CSPM) tool.

## What it does

Renders a logical AWS topology on a flat coordinate grid using Leaflet. Highlights misconfigured resources. Maps each finding to NIS2, NCSC CAF 4.0, and MITRE ATT&CK references with plain-English remediation guidance.

## Status

Under active development. Current focus: visualising a mock AWS environment with Leaflet and a normalised asset graph

## Tech stack

- **Backend:** Python 3.11+, FastAPI, boto3, pytest
- **Frontend:** Vanilla JavaScript, Leaflet (`L.CRS.Simple`), Tabler Icons
- **Compliance frameworks:** NIS2, NCSC CAF 4.0, MITRE ATT&CK (Cloud IaaS sub-matrix)

## Setup

Setup instructions will be added once the topology visualisation is in place.

## Author

Joseph Ademola — MSc Cybersecurity Risk & Resilience, University of South Wales.