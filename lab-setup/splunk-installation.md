# Splunk Installation Guide

## 1. Install Splunk Enterprise on SPLUNK VM

Download from: https://www.splunk.com/en_us/download/splunk-enterprise.html (Free license — up to 500MB/day)

```bash
# On Ubuntu 22.04 (SPLUNK VM)
wget -O splunk.deb "https://download.splunk.com/products/splunk/releases/9.x.x/linux/splunk-9.x.x-linux-amd64.deb"
sudo dpkg -i splunk.deb
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start
```

## 2. Create Indexes
Copy `configs/splunk/indexes.conf` to `$SPLUNK_HOME/etc/system/local/`
Restart Splunk: `sudo /opt/splunk/bin/splunk restart`

## 3. Install Splunk Universal Forwarder on WIN10-VICTIM and DC01

```powershell
# Run installer, then configure outputs.conf to point to SPLUNK VM IP
# $SPLUNK_HOME = C:\Program Files\SplunkUniversalForwarder
```

Copy `configs/splunk/inputs.conf` to:
`C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

Set forwarding destination:
```ini
# outputs.conf
[tcpout]
defaultGroup = splunk_server

[tcpout:splunk_server]
server = 192.168.10.30:9997
```

## 4. Verify Data Flow
In Splunk Web UI (http://192.168.10.30:8000):
```spl
index=endpoint | stats count BY host, sourcetype
index=wineventlog | stats count BY host, sourcetype
```
Both hosts should appear with event counts.
