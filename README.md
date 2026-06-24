# 🛡️ SOC Detection Engineering

This repository serves as a knowledge hub for the tools, configurations, rules, and scripts developed to extend and improve our SOC detection and incident response capabilities. It covers our security stack, including **Wazuh SIEM**, **CrowdStrike Falcon EDR**.


## 🔍 Wazuh V4.14.1-1 [`Wazuh/`](wazuh/)

This section covers everything developed around our Wazuh deployment, organized into the following areas:

### Detection Content
Custom **rules and decoders** developed to parse syslog sources not natively supported by Wazuh, extending visibility across our environment.

### Integrations & Enrichment
Processing pipelines and API integrations that enrich Wazuh alerts with additional context (e.g. GeoIP, threat intelligence).

### Configurations
Operational configurations and scripts to improve SIEM reliability and automate administrative tasks — including health monitoring, log source onboarding, and tuning.

---


