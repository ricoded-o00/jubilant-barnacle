# Secure Virtualized Cybersecurity Home Laboratory

## Overview

This project provides a blueprint for a professional-grade, software-defined cybersecurity laboratory. It utilizes **VMware ESXi** for robust virtualization, **pfSense** for high-performance network segmentation, and a **Docker-centric ecosystem** for lightweight service deployment. The entire environment is monitored by a **Splunk SIEM** to provide deep visibility into network traffic and endpoint behavior.

**Infografic-type, tl;dr version:** [Click here!](https://ricoded-o00.github.io/jubilant-barnacle/)

## Hardware Requirements

For optimal performance, particularly when running multiple Windows VMs and a Splunk indexer, the following specifications are recommended:

- **CPU:** Intel i7 or Ryzen 7 (Minimum 8 cores) to support concurrent virtualization.
    
- **RAM:** 32 GB to 64 GB DDR4 (16 GB is a functional minimum for smaller labs).
    
- **Storage:** 1 TB+ NVMe SSD for high IOPS during log ingestion.
    
- **Network:** At least two physical Gigabit NICs (one for WAN, one for out-of-band management) .
    

## Core Architecture

### 1. Hypervisor (Substrate)

- **Platform:** VMware ESXi 7.x or higher .
    
- **Hardening:** UEFI Secure Boot and TPM-based attestation are enabled to ensure boot chain integrity.
    
- **Virtual Switches:** Two vSwitches separate the "Untrusted" WAN from the "Trusted" internal lab .
    

### 2. Networking (Control Plane)

- **Gateway:** pfSense VM serving as the central firewall and inter-VLAN router.
    
- **Trunking:** Utilizes 802.1Q VLAN trunking via a VMware port group with **VLAN ID 4095** (Trunk Mode) to bypass the 10-vNIC limit .
    
- **Segments:**
    
    - **VLAN 10 (Management):** 10.10.10.0/24 (ESXi and pfSense GUI access) .
        
    - **VLAN 20 (Docker Tooling):** 10.10.20.0/24 (Security tools and containers).
        
    - **VLAN 50 (Isolated):** 10.10.50.0/24 (Fully air-gapped for malware analysis).
        

### 3. Service Layer (Compute)

- **Docker Host:** A minimalist Ubuntu Server VM running **Docker** and **Portainer** for container management.
    
- **Key Services:** Pi-hole (DNS filtering), DVWA (vulnerable app testing), and Cowrie (SSH honeypot).
    

### 4. SIEM & Logging (Visibility)

- **Indexer:** Splunk Enterprise running on a dedicated Linux VM.
    
- **Ingestion:** **Splunk Connect for Syslog (SC4S)** deployed as a container to parse pfSense filter logs.
    
- **Endpoints:** Universal Forwarders (UF) and **Sysmon** collect process-level telemetry from Windows hosts.
    

## Security Features

- **IDS/IPS:** Suricata enabled on the WAN interface using Snort VRT or ET Open rules.
    
- **DNS Filtering:** pfBlockerNG for GeoIP blocking and malicious domain blacklisting (DNSBL).
    
- **Remote Access:** **WireGuard VPN** with MFA/TOTP for secure, encrypted management from external networks.
    

## Implementation Checklist

1. **Hardware Prep:** Enable Intel VT-x/AMD-V and TPM in the BIOS.
    
2. **Hypervisor:** Install ESXi and configure vSwitch0 (WAN) and vSwitch1 (Internal) .
    
3. **Core Net:** Deploy pfSense, assign WAN/LAN, and configure the VLAN 4095 trunk .
    
4. **Logging:** Deploy Splunk and configure the HTTP Event Collector (HEC).
    
5. **Hardening:** Disable SSH on the hypervisor and implement "Lockdown Mode" .
    

## Disclaimer

This laboratory is intended for **educational and research purposes only**. Users are responsible for ensuring that all activities conducted within the lab comply with local laws and ethical hacking standards. Never scan or attack networks you do not explicitly own. Regular backups of the lab configuration are highly recommended.
