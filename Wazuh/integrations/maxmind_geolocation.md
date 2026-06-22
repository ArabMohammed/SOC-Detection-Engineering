# MaxMind GeoLite Database Integration

## Overview

Wazuh does not currently provide a built-in mechanism to automatically update the MaxMind GeoLite databases used for IP geolocation enrichment.
Keeping these databases up to date is important to ensure accurate geolocation information for source and destination IP addresses during investigations, threat hunting, and dashboard reporting.
To address this limitation, a monthly cron job can be configured to download the latest GeoLite databases from MaxMind and deploy them to the Wazuh Indexer GeoIP module.

---

## Prerequisites

Before using the update script, ensure that:

1. You have a valid MaxMind account.
2. You have generated a MaxMind License Key.

---

## Update Script

Replace the following placeholders before execution:

- `your_license_id`
- `your_license_key`

```bash
#!/bin/bash

set -e

WORKDIR="/tmp/geoip-update"
INSTALL_DIR="/usr/share/wazuh-indexer/modules/ingest-geoip"

LICENSE_ID="your_license_id"
LICENSE_KEY="your_license_key"

mkdir -p "$WORKDIR"
cd "$WORKDIR"

echo "Cleaning old files..."
rm -rf GeoLite2-*

echo "Downloading GeoLite2 Country..."
curl -L -u "${LICENSE_ID}:${LICENSE_KEY}" \
"https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz" \
-o GeoLite2-Country.tar.gz

tar -xzf GeoLite2-Country.tar.gz
cp GeoLite2-Country*/GeoLite2-Country.mmdb "$INSTALL_DIR"

echo "Downloading GeoLite2 City..."
curl -L -u "${LICENSE_ID}:${LICENSE_KEY}" \
"https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz" \
-o GeoLite2-City.tar.gz

tar -xzf GeoLite2-City.tar.gz
cp GeoLite2-City*/GeoLite2-City.mmdb "$INSTALL_DIR"

echo "Downloading GeoLite2 ASN..."
curl -L -u "${LICENSE_ID}:${LICENSE_KEY}" \
"https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz" \
-o GeoLite2-ASN.tar.gz

tar -xzf GeoLite2-ASN.tar.gz
cp GeoLite2-ASN*/GeoLite2-ASN.mmdb "$INSTALL_DIR"

echo "Setting permissions..."
chown wazuh-indexer:wazuh-indexer "$INSTALL_DIR"/GeoLite2-*.mmdb
chmod 644 "$INSTALL_DIR"/GeoLite2-*.mmdb

echo "Cleaning temporary files..."
rm -rf "$WORKDIR"

echo "GeoLite database update completed successfully."
```

---

## Cron Job Configuration

To automatically update the GeoLite databases on a monthly basis, add the following entry to the root user's crontab:

```cron
0 3 1 * * /opt/scripts/update-maxmind.sh >> /var/log/maxmind-update.log 2>&1
```

## Verification

After the script executes successfully, verify that the latest database files are present:

```bash
ls -lh /usr/share/wazuh-indexer/modules/ingest-geoip/
```

Expected files:

```text
GeoLite2-ASN.mmdb
GeoLite2-City.mmdb
GeoLite2-Country.mmdb
```
