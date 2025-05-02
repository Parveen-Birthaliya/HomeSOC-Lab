# SOC-ELK-Server

## Overview  
Centralized log ingestion, parsing, indexing, and visualization for Sysmon, Suricata, and Zeek telemetry.

---

## Infrastructure Details  
* Location: Toronto, Canada
* Machine Type:  Dedicated CPU

* Operating System: Ubuntu Server 24.04 LTS (64-bit)

* Resources Allocated:

  * vCPUs: 4 cores or 8 core

  * RAM: 16 GB

  * Storage: 100 GB SSD or 80 GB

* Network Configuration:

  * VPC 2.0: Enabled for private/internal network communication

* Firewall Rules:

  * SSH (Port 22): Allowed only for my IP

  * Kibana (Port 5601): Temporarily allowed for my IP



## Toola Installation Steps  

### Access Machine & Update the Machine
SSH into the machine using the following command
```bash
ssh root@server_ip
```
Then authenticate the ssh by entering
```bash
Yes
```
Enter Your Password , You can just copy the password from the vultr Machine discription and Paste it 
```bash
your_password
```
Now enter the following command to update and upgrade the machine
```bash
sudo apt-get update && sudo apt-get upgrade -y
```

### Elasticsearch installation & Configuration

1. **Googel Elasticsearch & Download**
 Google elastic search download, Click on the First website then choose the deb x86_64
 and then copy the download link and then  use the following Command to download
   ```bash
   wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-9.0.0-amd64.deb
   ```
   
2. **Unpacking Elasticsearch**
 ```bash
dpkg -i elasticsearch-9.0.0-amd64.deb
```
Copy the Security Autoconfiguration Mainly Password

3. **changing elasticsearch.config**
   Move to elastic config file directory
   ```bash
   cd /etc/elasticsearch
   ```
   use nano to edit config file
   ```bash
   nano elasticsearch.config
   ```
   uncomment  network.host and http.port and then just update network.host value
   ```bash
   network.host:your_ELK-Server_ip
   http.port:9200
   ```
4. **Creating Firewall and its rule for Our SOC lab**
   * SOC-ELK-Server -> Settings -> Firewall -> Manage -> Add firewall group
   * Enter Firewall Name Like : My-SOC-LAB-Firewall
   * write your first rule:
     **Inbound IPv4 Rules**

    | Action | Protocol | Port (or range) | Source               | Notes     |
    |--------|----------|-----------------|----------------------|-----------|
    | accept | SSH      | 22              | Anywhere (0.0.0.0/0) |    +      |
    | accept | SSH      | 22              |      myip            |           |
    | drop   | any      | 0–65535         | 0.0.0.0/0            | (default) |

 5. **Updating the ELK-Firewall**
    * OC-ELK-Server -> Settings -> Firewall -> DropDownMenu(My-SOC-LAB-Firewall)

 6.  **Enable & Start Service**

```bash
# Reload systemd configs
sudo systemctl daemon-reload

# Enable Elasticsearch at boot
sudo systemctl enable elasticsearch.service

# Start Elasticsearch now
sudo systemctl start elasticsearch.service

# Check Status of Elasticsearch now
sudo systemctl status elasticsearch.service
