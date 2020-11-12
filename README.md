# RHEL 6 & 7 Host Security Tool
This package consists of a host enumeration script, hostinfo.py, and an ansible playbook to copy the script and create a weekly cron job to run it.
### The script hostinfo.py: 
Identifies security-relevant data and sends it to your SIEM or syslog collector in key='value' syntax. There is an xml-user account scrubber included which could be easily modified for your environment if you are storing your user account data in xml. Before running hostinfo.py it is worth validating that the import modules do exist and are able to be installed in your environment. 
#### The ansible playbook ansible-playbook-hostinfo.yml:
Requires validating the directory paths and users you want to execute the playbook (may require adjustment for your environment). Items that need to be tweaked for your environment are identified with "{}". 
#####
Requires at least python 3.2.0 on either RHEL 6 or RHEL 7.
