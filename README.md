# Cloud Resilience Visualizer

A visual threat-modelling and AWS infrastructure compliance platform.

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

Setup instructions will be added once Phase 1 is complete.

## Author

Joseph Ademola — MSc Cybersecurity Risk & Resilience, University of South Wales.