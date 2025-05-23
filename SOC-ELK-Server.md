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
* Copy the Security Autoconfiguration Mainly Password

3. **changing elasticsearch.config**
   Move to elastic config file directory
```bash
   cd /etc/elasticsearch
```
   use nano to edit config file
 ```bash
   nano elasticsearch.yml
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


* Reload systemd configs
```bash
sudo systemctl daemon-reload
```
* Enable Elasticsearch at boot
```bash
sudo systemctl enable elasticsearch.service
```
* Start Elasticsearch now
```bash
sudo systemctl start elasticsearch.service
```
* Check Status of Elasticsearch now
```bash
sudo systemctl status elasticsearch.service
```
### Kibana installation & Configuration

1. **Googel Elasticsearch & Download**
 Google Kibana download, Click on the First website then choose the deb x86_64
 and then copy the download link and then  use the following Command to download
```bash
wget https://artifacts.elastic.co/downloads/kibana/kibana-9.0.0-amd64.deb
```
2. **Unpacking Elasticsearch**
 ```bash
dpkg -i kibana-9.0.0-amd64.deb
```
3. **changing kibana.config**
   Move to kibana config file directory
```bash
   cd /etc/kibana
```
   use nano to edit config file
```bash
   nano kibana.yml
```
   uncomment  server.host and server.port and then just update server.host value
```bash
   server.host:your_ELK-Server_ip
   server.port:5601
```
 4. **Enable & Start Service**


* Reload systemd configs
```bash
sudo systemctl daemon-reload
```
* Enable Kibana at boot
```bash
sudo systemctl enable kibana.service
```
* Start kibana now
```bash
sudo systemctl start kibana.service
```
* Check Status of kibana now
```bash
sudo systemctl status kibana.service
```
5. **Setup configuaration to access Web Server**
* Move to the following directory
```bash
cd /usr/share/elasticsearch/bin
```
* Get Enrollment Token & Copy the token and save it 
```bash
./elasticsearch-create-enrollment-token --scope kibana
```
* Add firewall rule to access kibana dashboard
  
  
  | TCP | 1-65535 | myip |

* Allow port 6501 in SOC-ELK-Server
```bash
ufw allow 5601
```
6. **Accessing Kibana Web Service**
* Access web using : https://elk-server-ip:5601
* Enter enrollment token we previously saved
* We can access verification code using the follwing command(In directory /usr/share/kibana/bin)
```bash
./kibana-verification-code
```
* Enter user-login
```bash
username: elastic
password: we saved when installing the elasticsearch( Security Autoconfiguration)
```
xpack.encryptedSavedObjects.encryptionKey:
xpack.reporting.encryptionKey: 
xpack.security.encryptionKey: 


7. **Adding Encryption Key**
* Get Key in /usr/share/kibana/bin
```bash
 ./kibana-encryption-keys generate
```
* Add these key to Kibana Keystore
```bash
   .kibana-keystore add xpack.encryptedSavedObjects.encryptionKey
```
Now enter the key 
```bash
   .kibana-keystore add xpack.reporting.encryptionKey
```
Now enter the key 
```bash
   .kibana-keystore add xpack.security.encryptionKey
```
Now enter the key 

* restart kibana
```bash
systemctl restart kibana.service
```

* Now relogin to kibana web service
