#!/usr/bin/env python3

##################################################################################
#
# Completed (v1.0) 04/2020 by Skip McGee
#
# Script to pull security-relevant Red Hat host information to build and
# maintain a current asset inventory of all hosts. Send the identified
# host details via syslog into Splunk. This script requires that appropriate
# syslog forwarding is configured on the host, and if using rsyslog,
# that the following entries are in /etc/rsyslog.conf or appropriate drop-in:
# $ModLoad imuxsock;$MaxMessageSize 500k;$PreserveFQDN on
# and that an appropriate query/report/dashboard is implemented in Splunk
# (or the network-appropriate syslog ingestion platform).
#
# This script should be run weekly on all Red Hat hosts across the enterprise.
# The data sent via this script on a randomly selected server was 184k,
# projected data usage on a network of 500 hosts would be  0.0109GB per week.
# On a network of ~100 hosts it will require storage support of ~0.34008GB
# over 3 years (log data retention policies may vary).
#
##################################################################################

# Import statements for all standard modules
import subprocess
from datetime import date
from datetime import timedelta
from datetime import datetime
import sys
import syslog
import logging
import logging.handlers
import os
import os.path
import glob
import re
import platform
# This may not be a standard module in your enterprise, so a yum install option is provided
try:
    import numpy as np
except ImportError:
    try:
        subprocess.call(["yum", "install", "-y", "python36-numpy"])
        import numpy as np
    except:
        try:
            subprocess.call(["yum", "install", "-y", "numpy"])
            import numpy as np
        except:
            pass
# Try installing pip, in case of issues later
try:
    import pip
except ImportError:
    try:
        subprocess.call(["yum", "install", "-y", "rh-python36-python-pip"])
        import pip
    except:
        try:
            subprocess.call(["yum", "install", "-y", "python-pip"])
            import pip
        except:
            pass
# Encouraged but not required non-standard modules
try:
    import netifaces
except ImportError:
    try:
        subprocess.call(["yum", "install", "-y", "python36-netifaces"])
        import netifaces
    except:
        subprocess.call(["yum", "install", "-y", "python-netifaces"])
        try:
            import netifaces
        except:
            try:
                subprocess.call(["pip", "install", "netifaces"])
                import netifaces
            except:
                pass
try:
    import psutil
except ImportError:
    try:
        subprocess.call(["yum", "install", "-y", "python36-psutil"])
        import psutil
    except:
        subprocess.call(["yum", "install", "-y", "python-psutil"])
        try:
            import psutil
        except:
            try:
               subprocess.call(["pip", "install", "psutil"])
               import psutil
            except:
                pass
# The only required non-standard module for parsing xmls in the organizational environment, enable if org users are stored in xml 
# and if you desire to use the inspect_accounts function detailed later
#try:
#    from lxml import etree
#except ImportError:
#    try:
#        subprocess.call(["yum", "install", "-y", "python36-lxml"])
#        from lxml import etree
#    except:
#        subprocess.call(["yum", "install", "-y", "python-lxml"])
#        try:
#            from lxml import etree
#        except:
#            try:
#                subprocess.call(["pip", "install", "lxml"])
#                from lxml import etree
#            except:
#                pass


# Define today's date to use to identify the running of this script
date = date.today()


# Define the Host Operating System, kernel version and date last updated
def osinfo():
        quikos = str(platform.dist())[1:-1]
        quikos = quikos.replace("', '", "-")
        bigos = str(platform.uname())[1:-1]
        bigos = bigos.replace("name_result(", "")
        bigos = bigos.replace("#1SMP", "")
        bigos = bigos.replace(" ", "")
        bigos = bigos.replace(",", "; ")
        osinfo = quikos + "; " + bigos
        return osinfo


# Define the Host's machine name
def hostname():
    hostname = platform.node()
    return hostname


# Define the Host's currently installed applications w/ version numbers and repos
def apps():
    apps_test = subprocess.call(["yum", "list", "installed"])
    if apps_test == 0:
        apps = subprocess.check_output(["yum", "list", "installed"]).decode("utf-8")
        apps = re.sub(r"\n+", ";", apps)
        apps = re.sub(r"\s+", "", apps)
        apps = re.sub(r"\t+", "", apps)
        apps = apps.replace(";", "; ")
        apps = re.sub(r"(@.*?;)", ";", apps, flags=re.MULTILINE)
        apps = apps.split(';')[4:]
        apps = ";".join(apps)
        apps = apps.replace(" ; ", " ")
        apps = apps[:len(apps) // 2]
        apps = apps[1:]
        apps = 'Installed_Packages1=' + "'" + apps + "'"
    else:
        apps = "Error with 'yum list installed' command"
    return apps
# Define 2nd half of package list in case the max message size is exceeded
def apps2():
    apps_test = subprocess.call(["yum", "list", "installed"])
    if apps_test == 0:
        apps = subprocess.check_output(["yum", "list", "installed"]).decode("utf-8")
        apps = re.sub(r"\n+", ";", apps)
        apps = re.sub(r"\s+", "", apps)
        apps = re.sub(r"\t+", "", apps)
        apps = apps.replace(";", "; ")
        apps = re.sub(r"(@.*?;)", ";", apps, flags=re.MULTILINE)
        apps = apps.split(';')[4:]
        apps = ";".join(apps)
        apps = apps.replace(" ; ", " ")
        apps2 = apps[len(apps) // 2:]
        apps2 = apps2[:-2]
        apps2 = 'Installed_Packages2=' + "'" + apps2 + "'"
    else:
        apps2 = "Error with 'yum list installed' command"
    return apps2


# Define the Host time in UTC, ntp sync status, etc.
def time():
    try:
        time_test = subprocess.call(["timedatectl"])
        if time_test == 0:
            time = subprocess.check_output(["timedatectl"]).decode("utf-8")
            time = re.sub(r"\n", "; ", time)
            time = time.replace(": ", "='")
            time = time.replace("  ", "")
            time = time.replace(" ", "_")
            time = time.replace(";", "'; ")
            time = time.replace(" _", " ")
            time = time.replace(",_", ",")
            time = time.split(";")
            time = time[0:8]
            time = ";".join(time)
        else:
            time = "Error with 'timedatectl' command"
    except:
        time_test2 = subprocess.call(["hwclock"])
        if time_test2 == 0:
            time = 'Time='
            clocktime = subprocess.check_output(["hwclock"]).decode(sys.stdout.encoding).strip()
            clocktime = "'" + clocktime + "'"
            time += clocktime
            str(time)
            ntp_cmd = "ntpstat"
            ntptimeout = subprocess.Popen([ntp_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True).communicate()[0]
            ntptimeerr = subprocess.Popen([ntp_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True).communicate()[1]
            ntptimeout = str(ntptimeout)
            ntptimeout.rstrip()
            ntptimeerr = str(ntptimeerr)
            ntptimeerr.rstrip()
            ntptimeout = ntptimeout.replace(" ", "_")
            ntptimeout = ntptimeout.replace("__", " ")
            if ntptimeout == '':
                syncstat = "; NTP_synchronized='no'"
                time += syncstat
            else:
                time += ntptimeout
        else:
            time = "Error with 'hwclock' and 'ntpstat' commands"
    return time


# Define the Host's network interfaces
def interfaces():
    try:
        interfaces = str(netifaces.interfaces())
        interfaces = str(interfaces)[1:-1]
        interfaces = interfaces.replace(" ", "")
        interfaces = interfaces.replace("','", ",")
    except NameError:
        try:
            interfaces = psutil.net_if_addrs()
            interfaces = interfaces.keys()
            interfaces = str(interfaces)
            interfaces = str(interfaces)[11:-2]
            interfaces = interfaces.replace("','", ",")
            interfaces = interfaces.replace("', '", ",")
# Including exception in case neither netifaces or psutil was available to be imported
        except:
            intf_cmd = "ifconfig | grep mtu | awk -F':' '{print $1}'"
            interfaces = subprocess.Popen([intf_cmd], stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, universal_newlines=True, shell=True).communicate()[0]
# Including the possibility of a Red Hat 6 host which has different ifconfig formatting
            if interfaces == '':
                rhel6_intf_cmd = "ifconfig | grep 'Link encap:' | awk '{print $1}'"
                interfaces = subprocess.Popen([rhel6_intf_cmd], stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, universal_newlines=True,
                                          shell=True).communicate()[0]
            interfaces = str(interfaces)
            interfaces = interfaces.splitlines()
            interfaces = str(interfaces)[1:-1]
            interfaces = interfaces.replace("','", ",")
            interfaces = interfaces.replace("', '", ",")
    return interfaces


# Define the Host's primary IP address
def ipaddrpri():
    ipaddrpri_cmd = r"hostname --all-ip-addresses | awk '{print $1}'"
    ipaddrpri = subprocess.Popen([ipaddrpri_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 encoding="utf-8", universal_newlines=True, shell=True).communicate()[0]
    ipaddrpri = str(ipaddrpri)
    ipaddrpri = ipaddrpri.rstrip()
    return ipaddrpri


# Define the Host's full interface information
def ifaddrall():
    try:
        ifaddrall = str(psutil.net_if_addrs())[1:-1]
        ifaddrall = ifaddrall.replace("snicaddr(family=<AddressFamily.AF_INET: 2>, ", "")
        ifaddrall = ifaddrall.replace("snicaddr(family=<AddressFamily.AF_PACKET: 17>, ", "")
        ifaddrall = ifaddrall.replace("snicaddr(family=<AddressFamily.AF_INET6=10>, ", "")
        ifaddrall = ifaddrall.replace("netmask='ffff:ffff:ffff:ffff::'", "")
        ifaddrall = ifaddrall.replace("netmask='ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'", "")
        ifaddrall = ifaddrall.replace("broadcast='ff:ff:ff:ff:ff:ff'", "")
        ifaddrall = ifaddrall.replace(": ", "=")
        ifaddrall = ifaddrall.replace("[", "{")
        ifaddrall = ifaddrall.replace("]", "}")
        ifaddrall = ifaddrall.replace(")", "")
        ifaddrall = ifaddrall.replace(" ", "")
        ifaddrall = ifaddrall.replace(",ptp=None", "")
        ifaddrall = ifaddrall.replace(",broadcast=None", "")
        ifaddrall = ifaddrall.replace(",netmask=None", "")
    except NameError:
        ifaddrall_err = " Error with psutil.net_if_addrs(), check if psutil version >= 3.0, only returning IP information"
        ifaddrall_cmd = r"ip addr | for x in 'grep inet'; do echo $(awk -F'[ /]' '/inet /{print $6}'); done"
        ifaddrall = subprocess.Popen([ifaddrall_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     encoding="utf-8", universal_newlines=True, shell=True).communicate()[0]
        ifaddrall = str(ifaddrall)
        ifaddrall = ifaddrall.strip()
        ifaddrall = ifaddrall.replace(" ", ",")
        ifaddrall = "'" + ifaddrall + "'"
        ifaddrall += ifaddrall_err
    return ifaddrall


# Define the Host's mac addresses
def macaddr():
    try:
        macaddr_cmd = r"ifconfig | grep ether | awk '{print $2}'"
        macaddr = subprocess.Popen([macaddr_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8", universal_newlines=True, shell=True).communicate()[0]
        macaddr = re.sub(r"\s+", ", ", macaddr)
        macaddr = macaddr.strip()[:-1]
        macaddr = "'" + macaddr + "'"
# Including the possibility of a RedHat 6 host which has different ifconfig formatting
        if macaddr == "''":
            rhel6_mac_cmd = "ifconfig | grep HWaddr | awk '{print $5}'"
            macaddr = subprocess.Popen([rhel6_mac_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8", universal_newlines=True, shell=True).communicate()[0]
            macaddr = macaddr.rstrip()
            macaddr = "'" + macaddr + "'"
    except:
        macaddr = "'Error with macaddr function'"
    return macaddr


# Define the Serial Number, Asset Tag (if tagged), Manufacturer, Make/Model and BIOS information
def hwinfo():
    a = "Vendor:"
    b = "Version:"
    c = "Release Date:"
    d = "BIOS Revision:"
    e = "Firmware Revision:"
    f = "Manufacturer:"
    g = "Product Name:"
    h = "Serial Number:"
    i = "UUID:"
    j = "Serial Number:"
    k = "Asset Tag:"
    worthless = "Not Specified"
    try:
    # some organizations dump dmidecode data into a file like /etc/dmidump on a regular basis
        with open('/etc/dmidump', encoding="utf-8") as file:
            hwinfo1 = file.read()
            file.close()
            hwinfo1 = hwinfo1.splitlines()
            hwinfo = []
            for line in hwinfo1:
                if line not in hwinfo:
                    if worthless in line:
                        continue
                    if a in line:
                        if line not in hwinfo:
                            hwinfo.append(line)
                    if b in line:
                        if line not in hwinfo:
                            hwinfo.append(line)
                    if c in line:
                        if line not in hwinfo:
                            hwinfo.append(line)
                    if d in line:
                        if line not in hwinfo:
                            hwinfo.append(line)
                    if e in line:
                        if line not in hwinfo:
                            hwinfo.append(line)
                    if f in line:
                        if line not in hwinfo:
                            hwinfo.append(line)
                    if g in line:
                        if line not in hwinfo:
                            hwinfo.append(line)
                    if h in line:
                        if line not in hwinfo:
                            hwinfo.append(line)
                    if i in line:
                        if line not in hwinfo:
                            hwinfo.append(line)
                    if k in line:
                        if line not in hwinfo:
                            hwinfo.append(line)
            hwinfo = ''.join(hwinfo)
            hwinfo = hwinfo.replace("\n", "")
            hwinfo = hwinfo[1:]
            hwinfo = hwinfo.replace("\t", ";")
            hwinfo = hwinfo.replace(" ", "")
            hwinfo = hwinfo.replace(":", "='")
            hwinfo = hwinfo.replace(";", "'; ")
            hwinfo = hwinfo + "'"
    except:
        hwinfo_test = subprocess.call(["dmidecode --type 0,1,3"], shell=True)
        if hwinfo_test == 0:
            hwinfo1 = subprocess.check_output(["dmidecode --type 0"], shell=True).decode("utf-8")
            hwinfo1 = hwinfo1.splitlines()
            hwinfo = []
            for line in hwinfo1:
                if worthless in line:
                    continue
                if a in line:
                    hwinfo.append(line)
                if c in line:
                    hwinfo.append(line)
                if d in line:
                    hwinfo.append(line)
                if e in line:
                    hwinfo.append(line)
            hwinfo2 = subprocess.check_output(["dmidecode --type 1"], shell=True).decode("utf-8")
            hwinfo2 = hwinfo2.splitlines()
            for line in hwinfo2:
                if worthless in line:
                    continue
                if b in line:
                    hwinfo.append(line)
                if f in line:
                    hwinfo.append(line)
                if g in line:
                    hwinfo.extend(line)
                if h in line:
                    hwinfo.extend(line)
                if i in line:
                    hwinfo.append(line)
            hwinfo3 = subprocess.check_output(["dmidecode --type 3"], shell=True).decode("utf-8")
            hwinfo3 = hwinfo3.splitlines()
            for line in hwinfo3:
                if worthless in line:
                    continue
                if k in line:
                    hwinfo.append(line)
            hwinfo = ''.join(hwinfo)
            hwinfo = hwinfo.replace("\n", "")
            hwinfo = hwinfo[1:]
            hwinfo = hwinfo.replace("\t", ";")
            hwinfo = hwinfo.replace(" ", "")
            hwinfo = hwinfo.replace(":", "='")
            hwinfo = hwinfo.replace(";", "'; ")
            hwinfo = hwinfo + "'"
        else:
            hwinfo = "'/etc/dmidump' does not exist on {hostname} and error with the 'dmidecode --type 0,1,3' command".format(hostname=hostname)
    return hwinfo


# Define the current open ports on the host
def netstat():
    netstat_test = subprocess.call(["netstat", "-noplv", "--inet"])
    if netstat_test == 0:
        netstat = subprocess.check_output(["netstat", "-noplv", "--inet"]).decode("utf-8")
        netstat = re.sub(r"^\bnetstat: no support\b.*\n+", " ", netstat, flags=re.MULTILINE)
        netstat = netstat[43:]
        netstat = re.sub(r"\n", ";", netstat)
        netstat = netstat.replace("\\n", "")
        netstat = re.sub(r"\t", "", netstat)
        netstat = re.sub(r"\s+", " ", netstat)
        netstat = netstat.replace("  ", "")
        netstat = netstat.replace(";", "; ")
        netstat = netstat[:-2]
        netstat = netstat.strip()
        netstat = "Active_Sockets=" + "'" + netstat + "'"
    else:
        netstat = "Error with 'netstat -noplv --inet' command"
    return netstat


# Define the current status of SELinux (enabled / disabled / permissive /enforcing)
def sestatus():
    sestatus_test = subprocess.call(["sestatus"])
    if sestatus_test == 0:
        sestatus = subprocess.check_output(["sestatus"]).decode("utf-8")
        sestatus = re.sub(r"\s+", " ", sestatus, flags=re.MULTILINE)
        sestatus = sestatus.strip()
        sestatus = sestatus.replace(": ", "='")
        sestatus = sestatus.replace(" ", "")
        sestatus = sestatus.replace("SELinuxfsmount", "', SELinuxfsmount")
        sestatus = sestatus.replace("Currentmode", "', Currentmode")
        sestatus = sestatus.replace("Modefromconfigfile", "', Modefromconfigfile")
        sestatus = sestatus.replace("Policyversion", "', Policyversion")
        sestatus = sestatus.replace("Policyfromconfigfile", "', Policyfromconfigfile")
        sestatus = sestatus.replace("SELinuxrootdirectory", "', SELinuxrootdirectory")
        sestatus = sestatus.replace("Loadedpolicyname", "', Loadedpolicyname")
        sestatus = sestatus.replace("PolicyMLSstatus", "', PolicyMLSstatus")
        sestatus = sestatus.replace("Policydeny_unknownstatus", "', Policydeny_unknownstatus")
        sestatus = sestatus.replace("Maxkernelpolicyversion", "', Maxkernelpolicyversion")
        sestatus = sestatus + "'"
    else:
        sestatus = str("Error_with_'sestatus'")
    return sestatus


# Define all user accounts on the host
def user_accounts():
    with open('/etc/passwd', 'r') as file:
        search_string = "nologin"
        accounts = ''
        for line in file:
            if search_string not in line:
                accounts += line
        accounts = re.sub(r"^\bsync\b.*\n+", " ", accounts, flags=re.MULTILINE)
        accounts = re.sub(r"^\bshutdown\b.*\n+", " ", accounts, flags=re.MULTILINE)
        accounts = re.sub(r"^\bhalt\b.*\n+", " ", accounts, flags=re.MULTILINE)
        accounts = re.sub(r"^\broot\b.*\n+", " ", accounts, flags=re.MULTILINE)
        accounts = re.sub(r"^\s+\bsync\b.*\n+", " ", accounts, flags=re.MULTILINE)
        accounts = re.sub(r"^\s+\bshutdown\b.*\n+", " ", accounts, flags=re.MULTILINE)
        accounts = re.sub(r"^\s+\bhalt\b.*\n+", " ", accounts, flags=re.MULTILINE)
        accounts = re.sub(r"^\s+\broot\b.*\n+", " ", accounts, flags=re.MULTILINE)
        accounts = accounts.replace("\n", ";")
        accounts = accounts.replace("\\n", "")
        accounts = accounts.replace("\t", "")
        accounts = accounts.replace(" ", "")
        accounts = accounts.replace(";", "; ")
        accounts = accounts[:-2]
        accounts = accounts.strip()
        file.close()
        return accounts


# Define all user monikers for accounts on the host
def monikers():
    with open('/etc/passwd', 'r') as file:
        search_string = "nologin"
        a = "sync"
        b = "shutdown"
        c = "halt"
        d = "root"
        accounts = ''
        monikers = []
        for line in file:
            if search_string not in line:
                accounts += line
        for line in accounts.splitlines():
            word = line.split(':x:')
            word = [word[0]]
            if a in word:
                continue
            if b in word:
                continue
            if c in word:
                continue
            if d in word:
                continue
            else:
                monikers.extend(word)
        monikers = str(monikers)[1:-1]
        monikers = monikers.replace("', '", "; ")
        file.close()
        return monikers


# Define all non-enterprise accounts (note: requires the enterprise account list to be in xml in a directory available to the local host)
#def inspect_accounts():
# Check for one of 2 different filepaths and determine the appropriate directory to pull user information from
# These filepaths must match your organizational environment in order to use this function
#    if os.path.isfile('/usr/local/share/fakepath.xml') == True: 
        # specify first filepath
#        userspath = '/usr/local/share/fakepath.xml'
#    elif os.path.isfile('/etc/sysconfig/fakepath.xml') == True:
        # specify second filepath
#        userspath = '/etc/sysconfig/fakepath.xml'
#    else:
#        non_org_users = []
#        with open('/etc/passwd', 'r') as file7:
#            search_string = "nologin"
#            for line in file7:
#                if search_string not in line:
#                    a = "sync"
#                    b = "shutdown"
#                    c = "halt"
#                    d = "root"
#                    if a not in line:
#                        if b not in line:
#                            if c not in line:
#                                if d not in line:
#                                    line.splitlines()
#                                    word = line.split(':x:')
#                                    word = [word[0]]
#                                    non_org_users.extend(word)
#                                else:
#                                   continue
#                            else:
#                                continue
#                        else:
#                            continue
#                    else:
#                        continue
#        file7.close()
#        non_org_users.append(r"Confirm that {hostname}=NON-ORGANIZATIONAL_host: error finding the fakepath.xml prevents parsing non-org-users".format(hostname=hostname()))
#        return non_org_users
#    with open(userspath, 'r') as file:
#        org_users = []
#        non_org_users = []
#        xml = file.read()
#        root = etree.fromstring(xml)
#        for user in root.getchildren():
#            for username in user.getchildren():
#                if username.tag == "username":
#                    org_users += [username.text]
#        with open('/etc/passwd', 'r') as file2:
#            search_string = "nologin"
#            for line in file2:
#                if search_string not in line:
#                    line.splitlines()
#                    word = line.split(':x:')
#                    word = [word[0]]
#                    moniker = np.setdiff1d(word,org_users,assume_unique=False).tolist()
#                    moniker = list(moniker)
#                    if moniker not in non_org_users:
#                        non_org_users.extend(moniker)
#            non_org_users2 = ''
#            a = "sync"
#            b = "shutdown"
#            c = "halt"
#            d = "root"
#            for item in non_org_users:
#                if a == item:
#                    continue
#                if b == item:
#                    continue
#                if c == item:
#                    continue
#                if d == item:
#                    continue
#                if item != []:
#                    item = item + '; '
#                    non_org_users2 += item
#            non_org_users2 = non_org_users2[:-2]
#            if non_org_users2 == '':
#                non_org_users2 = "{hostname}'s /etc/passwd entries match the organizational listing".format(hostname=hostname())
#        file2.close()
#    file.close()
#    return non_org_users2


# Define all service accounts on the host
def service_accounts():
    with open('/etc/passwd', 'r') as file3:
        search_string = "nologin"
        accounts = ''
        for line in file3:
            if search_string in line:
                accounts += line
            a = "root"
            b = "sync"
            c = "shutdown"
            d = "halt"
            if a in line:
                accounts += line
            if b in line:
                accounts += line
            if c in line:
                accounts += line
            if d in line:
                accounts += line
        accounts = accounts.replace("\n", ";")
        accounts = accounts.replace("\\n", "")
        accounts = accounts.replace("\t", "")
        accounts = accounts.replace(" ", "")
        accounts = accounts.replace(";", "; ")
        accounts = accounts[:-2]
        accounts = accounts.strip()
        accounts = "'" + accounts + "'"
        file3.close()
        return accounts


# Define the sudoers privileges on the host
# Note that some organizations may use multiple sudoers files so we need to consider more than just /etc/sudoers
def sudoers():
    try:
        sudoers_flist = []
        for file in glob.glob('/etc/sudoers.d/*'):
            sudoers_flist.append(file)
        for file in sudoers_flist:
            file = file.rstrip()
            with open(file, 'r', encoding='utf-8') as sudoers10, open('/etc/temp.txt', 'a+', encoding='utf-8') as sudoersout:
                sudoers10 = sudoers10.read()
                sudoersout.write(sudoers10)
        with open('/etc/sudoers', 'r', encoding='utf-8') as sudoers1, open('/etc/temp.txt', 'a+', encoding='utf-8') as sudoersout:
            sudoers1 = sudoers1.read()
            sudoersout.write(sudoers1)
        with open('/etc/temp.txt', 'r', encoding='utf-8') as sudoersout:
            sudoers = sudoersout.read()
    except FileNotFoundError:
        with open('/etc/sudoers', 'r', encoding="utf-8") as file6:
            sudoers = file6.read()
            file6.close()
    finally:
        sudoers = re.sub(r'(?m)^ *#.*\n?', '', sudoers, flags=re.MULTILINE)
        sudoers = re.sub(r'^\bDefaults\b.*\n', '', sudoers, flags=re.MULTILINE)
        sudoers = re.sub(r'^\bDEFAULT\b.*\n', '', sudoers, flags=re.MULTILINE)
        sudoers = re.sub(r'^$\n', '', sudoers, flags=re.MULTILINE)
        sudoers = sudoers.replace(" ", "")
        sudoers = sudoers.replace("\n", "; ")
        sudoers = sudoers.replace("\\n", "")
        sudoers = sudoers.replace("ALL", "")
        sudoers = sudoers.replace("ALL=(ALL)", "")
        sudoers = sudoers.replace("=()", "")
        sudoers = sudoers.replace("\t", "")
        sudoers = sudoers[0:-2]
        sudoers = sudoers.replace("Host_Alias", "Host_Alias:")
        sudoers = sudoers.strip()
        sudoers = "'" + sudoers + "'"
        return sudoers


# Define the age of the root password and compare its last-change-date to the frequency it is supposed to be changed
# (every 180 days per NIST policy). 179 days is used here to ensure we have leeway to fix accounts and not violate the policy.
def root_change():
    root_test = subprocess.call(["chage", "-l", "root"])
    if root_test == 0:
        root_change = subprocess.check_output(["chage", "-l", "root"]).decode("utf-8")
        root_change = str(root_change)
        regex = r"(\w{3})+\s+([0-9]{2})+\,+\s+([0-9]{4})|$"
        root_change = re.search(regex, root_change)
        root_change = root_change.group(0)
        root_change = datetime.strptime(root_change, "%b %d, %Y")
        today = datetime.now()
        if (root_change + timedelta(days = 179)) <= today:
            root_change = "CHANGE_ROOT_PASSWORD, last_root_changed='{root_change}'".format(root_change=root_change)
        else:
            root_change = "Root_password_current, last_root_changed='{root_change}'".format(root_change=root_change)
    else:
        root_change = "Error with the 'chage -l root' command"
    return root_change


# Build log entries and sends them to syslog
def logs():
# Define Messages
    date_msg = "HostInfo_LastSent='{date}'; OS={osinfo}".format(date=date, osinfo=osinfo())
    apps_msg = "{apps}".format(apps=apps())
    apps_msg2 = "{apps2}".format(apps2=apps2())
    intf_msg = "Interface_Names={interfaces}; Primary_IP='{ipaddrpri}'; MAC_Address(es)={macaddr}".format(interfaces=interfaces(), ipaddrpri=ipaddrpri(), macaddr=macaddr())
    addr_msg = "All_Interface_Address_Info=[{ifaddrall}]".format(ifaddrall=ifaddrall())
    hw_msg = "{hwinfo}".format(hwinfo=hwinfo())
    user_msg = "User_Accounts='{user_accounts}'".format(user_accounts=user_accounts())
    moniker_msg = "Monikers={monikers}".format(monikers=monikers())
    service_msg = "Service_Accounts={service_accounts}".format(service_accounts=service_accounts())
    sudoers_msg = "Sudoers_Entries={sudoers}".format(sudoers=sudoers())
# Add this once the the enterprise user list directory is input into inspect_accounts() 
#    prop_msg = "Local_accountsORl33t_hackerz?='{inspect_accounts}'".format(inspect_accounts=inspect_accounts())


# Define Logger and send Log Messages (should be sent via rsyslog to the centralized log host / Splunk and stored in /var/log/messages)
    class SyslogFormatter(logging.Formatter):
        def format(self, record):
            result = super().format(record)
            return "ufeff" + result
    handler = logging.handlers.SysLogHandler('/dev/log', facility=syslog.LOG_AUTHPRIV)
    formatter = SyslogFormatter(logging.BASIC_FORMAT)
    handler.setFormatter(formatter)
    isrhostlog = logging.getLogger()
    isrhostlog.setLevel(os.environ.get("LOGLEVEL", "WARNING"))
    isrhostlog.addHandler(handler)
    logging.warning('%s', date_msg)
    logging.warning('%s', apps_msg)
    logging.warning('%s', apps_msg2)
    logging.warning('%s', intf_msg)
    logging.warning('%s', time())
    logging.warning('%s', addr_msg)
    logging.warning('%s', hw_msg)
    logging.warning('%s', netstat())
    logging.warning('%s', root_change())
    logging.warning('%s', sestatus())
    logging.warning('%s', user_msg)
    logging.warning('%s', service_msg)
    logging.warning('%s', sudoers_msg)
    logging.warning('%s', moniker_msg)
# Add this once the enterprise user list directory is input into inspect_accounts() 
#    logging.warning('%s', prop_msg)


# Define the main
def main():
    try:
        logs()
        os.remove('/etc/temp.txt')
    except:
        sys.stderr.write("Issues running the hostinfo.py logging script on %s, need to investigate why \n", hostname())
        class SyslogFormatter(logging.Formatter):
            def format(self, record):
                result = super().format(record)
                return "ufeff" + result
        handler = logging.handlers.SysLogHandler('/dev/log')
        formatter = SyslogFormatter(logging.BASIC_FORMAT)
        handler.setFormatter(formatter)
        isrhostlog = logging.getLogger()
        isrhostlog.setLevel(os.environ.get("LOGLEVEL", "WARNING"))
        isrhostlog.addHandler(handler)
        logging.warning("At least one log message failed on %s while running the hostinfo.py logging script", hostname())
        exit(1)
    return


# Call the main function
if __name__ == "__main__":
    main()
    exit()
