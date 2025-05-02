# SOC-Window-Server 

## Overview  
Windows Server 2022 endpoint configured with Sysmon, Elastic Agent, and C2 agent for telemetry generation and blue team analysis.

## Infrastructure Details
* Location: Toronto, Canada
* Machine Type: Shared CPU

* Operating System: Windows Server 2022 Standard

* Resources Allocated:

  * vCPUs: 1 cores

  * RAM: 2 GB

  * Storage: 55 GB SSD

* Network Configuration:

  * VPC 2.0: Enabled for private/internal network communication
## Access Machine 

1. **In debian/Linux OS**

* I have ubuntu as main OS so I installed remmina and then entered the  detail of the machine

2. **Windows**
* Use Remote Desktop and enter all details
  
## Sysmon Setup
**Download Sysmon**
- Access Window Server
- Search for sysmon download and click on first website then download sysmon
- Extract the Sysmon
** Download Sysmon moduler
- Search sysmon moduler github (olafhortang)
- click on sysmonconfig.xml and then click raw and save it
- Put it into extracted sysmon folder
**Installing Sysmon**
  ```bash
  .\Sysmon64.exe -i sysmonconfig.xml
  ```
  
