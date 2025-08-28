# Elastic-Stack-SOC-Simulation

## Project Overview

This project is a defensive security simulation lab designed to replicate the core workflows of a Security Operations Center (SOC) analyst.

## The focus:-

•	Collect logs from a Windows endpoint with Sysmon

•	Ingest them via Winlogbeat → Logstash → Elasticsearch → Kibana (ELK)

•	Simulate adversary behavior with Atomic Red Team

•	Detect & Triage attacks using MITRE ATT&CK–mapped rules

•	Document incident response workflows and tuning steps

## Why I built this:-

•	To practice real SOC workflows - log collection, triage, false-positive tuning, and reporting.

•	To showcase hands on blue team capability beyond theoretical knowledge.

•	To build a portfolio ready case study demonstrating skills in SIEMs, incident response, and detection engineering.

## Architecture & Lab Setup

### Tools Used:-

•	Endpoint: Windows 11 (VMware Fusion), Sysmon, Winlogbeat

•	SIEM: Elastic Stack (7.x/8.x), custom Logstash filters, Kibana dashboards

•	Adversary Simulation: Atomic Red Team, PowerShell

•	Detection Mapping: MITRE ATT&CK Navigator

•	Other Utilities:

            Process Explorer (for verification)
            
            Event Viewer (cross-check raw logs)
            
            Sigma (rule-writing framework)

### Deployment Steps 

#### 1. Set up the Lab Environment

•	Host Machine: MacBook (your main workstation).

•	Virtualization: VMware Fusion with a Windows 11 ARM64 VM.

•	Networking: NAT mode (so the VM could talk to your Mac-hosted Elastic Stack).

Why this setup?

•	Lightweight and easy to reset.

•	Kept the logs flowing into ELK without complex firewalling.
 
#### 2. Install and Configure Sysmon on Windows VM

•	Downloaded Sysmon from Microsoft Sysinternals.

•	Applied SwiftOnSecurity’s Sysmon config.

          Collected key event IDs:
              1 = Process Creation
              3 = Network Connections
              7 = Image Loads
              10 = Process Access
              11 = File Create
              
          Removed noisy events to reduce log volume.
         
This ensured visibility into process execution chains, suspicious network traffic, and credential dumping attempts.
 
#### 3. Install and Configure Winlogbeat

•	Installed Winlogbeat (Elastic’s Windows log forwarder).

•	Edited winlogbeat.yml:

      Enabled sysmon channel and security logs.
      Set Logstash as output. Example config:
    
          output.logstash:
          hosts: ["<Mac_IP>:5044"]
         
•	Tested connection with:

.\winlogbeat.exe test config -c .\winlogbeat.yml -e

This forwarded raw Windows events + Sysmon logs into Mac’s ELK stack.


#### 4. Deploy Elastic Stack on Mac

•	Used Docker Compose to quickly spin up:

    Elasticsearch (data storage)
    Kibana (visualization + rule writing)
    Logstash (parsing pipeline)

Basic docker-compose.yml: version: '3'

 services:

   elasticsearch:
  
    image: docker.elastic.co/elasticsearch/elasticsearch:8.9.0
    
    ports: - "9200:9200"
      
   kibana:
  
    image: docker.elastic.co/kibana/kibana:8.9.0
    
    ports: - "5601:5601"
      
   logstash:
  
    image: docker.elastic.co/logstash/logstash:8.9.0
    
    ports: - "5044:5044"

By running locally, can avoid cloud costs and have full control over configs.

 
#### 5. Build Logstash Pipeline

•	Created custom pipeline config at:

      /usr/share/logstash/pipeline/winlogbeat.conf

##### Example filter snippet:

filter {

  if [event_id] == 1 {
  
  mutate { add_field => { "event_description" => "Process Creation" } }
    
  }
  
  }



•	Validated with:

       logstash -f winlogbeat.conf --config.test_and_exit

This normalized Sysmon logs into Elastic Common Schema (ECS) for easier querying.
 
#### 6. Verify Logs in Kibana

•	Opened Kibana → Discover tab.

•	Confirmed:

       process.name: powershell.exe logs appeared.
       Parent-child relationships (e.g., winword.exe → powershell.exe) were visible.
       
•	Created custom dashboard showing:
        
       Top processes executed.
       Top users running commands.
       Network connections by destination IP.

 
#### 7. Simulated Adversary Behavior

•	Installed Atomic Red Team on the Windows VM.

•	Ran selected tests (PowerShell abuse, WMI exec, LSASS dump).

•	Observed:

    Sysmon captured event IDs.
    Winlogbeat forwarded to ELK.
    Alerts fired in Kibana as per your detection rules.
    
 This step validated that the SIEM pipeline could detect MITRE ATT&CK techniques in practice.


### Step-by-Step Workflow

#### 1. Baseline the Environment
   
•	Collected 24h of clean baseline logs with no attack simulation.

•	Measured:

   Avg Sysmon EventID=1 (process creation) per hour.
   
   Avg network connections initiated per host.
   
•	Result: ~2,000 process creation events/hr (normal background noise).

#### 2. Run Atomic Red Team Simulations

##### Example 1: Suspicious PowerShell Execution (T1059.001)

Invoke-AtomicTest T1059.001 -TestNumbers 1

•	Spawns PowerShell with base64-encoded commands.

•	Sysmon logs EventID=1 (Process Create) with suspicious command line.

    Kibana detection rule:
        IF process_name:powershell.exe AND command_line:*base64* → trigger High severity alert.
        
##### Example 2: WMI Execution (T1047)

Invoke-AtomicTest T1047
    Spawns processes via WmiPrvSE.exe.
    
    Detection rule:
         IF parent_process_name:WmiPrvSE.exe AND child_process_name NOT IN (wmiprvse.exe, svchost.exe) → Suspicious WMI Execution.
         
##### Example 3: Credential Dumping Simulation (T1003.001 - LSASS)

Invoke-AtomicTest T1003.001 -TestNumbers 1

•	Attempts to access lsass.exe memory.

•	Sysmon EventID=10 (Process Access) logs handle access to LSASS.

    Detection rule:
         IF target_process_name:lsass.exe AND granted_access:0x1410 → alert.
         

 
#### 3. Detection Engineering

•	Wrote Elastic detection rules for:

      Encoded PowerShell commands
      WMI spawning child processes
      LSASS memory access
      Abnormal parent-child relationships (e.g., Office spawning PowerShell)
      
•	Each rule mapped to MITRE ATT&CK techniques.

##### Example Rule Snippet (KQL in Kibana):

      process.executable : "powershell.exe" and process.command_line : "*-enc*"


#### 4. Incident Response Workflow (Playbook)

1.	Validate alert: confirm unusual process lineage in Kibana.
   
2.	Scope: pivot by host, user, time window; identify related processes.
   
3.	Containment : isolate host or terminate malicious process.
   
4.	Eradication/Recovery: remove persistence (if created), reset credentials.
   
5.	Document: write full incident report.






