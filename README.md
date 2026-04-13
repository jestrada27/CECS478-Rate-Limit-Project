# HTTP Request Monitoring and Rate-Limiting Defense System

## Project Summary
This project is a lightweight security-focused web application defense system built for the CECS 478 final project. The system monitors incoming HTTP requests, detects suspicious behavior based on request frequency, and applies rate limiting to reduce the impact of denial-of-service style traffic and automated bot activity.

The goal is to show how a simple defensive design can improve server availability and performance in a reproducible Docker-based environment.

## Core Features
- Flask web server with test endpoints
- Request monitoring per client
- Threshold-based rate limiting
- JSON or CSV logging of allowed and blocked requests
- Simple attack script to simulate abusive traffic
- Reproducible setup using Docker and Make

## Repository Structure
```text
.
├── app/                    # Flask app and monitoring logic
├── scripts/                # Traffic generation and demo scripts
├── artifacts/
│   └── alpha/              # Evidence for milestone submissions
├── docs/                   # Proposal diagram and notes
├── .github/workflows/      # CI workflow stubs
├── README.md
├── LICENSE
├── docker-compose.yml
├── Makefile
├── requirements.txt
└── project-board.md
```

## Setup Overview
### Prerequisites
- Docker
- Docker Compose
- GNU Make

### One-command bootstrap
```bash
make bootstrap
```

### Start the project
```bash
make up
```

### Stop the project
```bash
make down
```

### Run a basic demo attack
```bash
make demo
```

## Planned Evaluation
The system will be evaluated using:
- number of blocked malicious requests
- response time before and after rate limiting
- suspicious activity alerts
- false positive rate under normal traffic

## Milestones
- Proposal: repo skeleton, architecture diagram, written plan
- Alpha: end-to-end vertical slice with one endpoint, one attack script, one metric log
- Beta: feature-complete monitoring and rate limiting, stronger tests, charts/tables
- Final: reproducible release with frozen artifacts, report, and demo
