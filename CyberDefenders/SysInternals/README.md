# SysInternals

- [SysInternals](#sysinternals)
  - [Overview](#overview)
  - [Answer List](#answer-list)
  - [Walkthrough](#walkthrough)
  - [References](#references)

## Overview
Answer list as well as the walkthrough for each question.

[Link to challenge page](https://cyberdefenders.org/blueteam-ctf-challenges/100#nav-overview)

Category: Endpoint Forensics

Tools used:
- [FTK Imager](https://www.exterro.com/ftk-imager) v4.7.1.2
- [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) v1.58
- [Registry Explorer](https://ericzimmerman.github.io/#!index.md) v2.0.0.0
- [Strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings) v2.54
- VirusTotal

## Answer List
**Q1: What was the malicious executable file name that the user downloaded?**
> 9471e69c95d8909ae60ddff30d50ffa1

**Q2: When was the last time the malicious executable file was modified? 12-hour format**
> 11/15/2022 09:18:51 PM

**Q3: What is the SHA1 hash value of the malware?**
> fa1002b02fc5551e075ec44bb4ff9cc13d563dcf

**Q4: What is the malware's family?**
> rozena

**Q5: What is the first mapped domain's Fully Qualified Domain Name (FQDN)?**
> www.malware430.com

**Q6: The mapped domain is linked to an IP address. What is that IP address?**
> 192.168.15.10

**Q7: What is the name of the executable dropped by the first-stage executable?**
> vmtoolsIO.exe

**Q8: What is the name of the service installed by 2nd stage executable?**
> VMwareIOHelperService

**Q9: What is the extension of files deleted by the 2nd stage executable?**
> pf

## Walkthrough
**Load the image into FTK**

Extract zip file. Only one file:
- `SysInternals.E01`

In FTK, click `File` -> `Image Mounting...` and mount `SysInternals.E01` as a drive. *Example uses E drive.*

<img src="images/q0_mount_image_ftk.png" alt="FTK: Mount image" width="50%" height="50%"> <br>

Nothing will show up in the main FTK screen.

Click `File` -> `Add Evidence Item...` -> `Logical Drive`.

<img src="images/q0_add_logical_drive.png" alt="FTK: Add logical drive" width="35%" height="35%"> <br>

Select the new drive from the dropdown menu.

<img src="images/q0_select_drive.png" alt="FTK: Select drive" width="35%" height="35%"> <br>

It should appear in the Evidence Tree.

<img src="images/q0_evidence_tree.png" alt="FTK: Evidence added" width="20%" height="20%"> <br>

---
<br>

**Q1: What was the malicious executable file name that the user downloaded?**
> 9471e69c95d8909ae60ddff30d50ffa1

The executable is at `[root]\Users\Public\Downloads\SysInternals.exe`.

<img src="images/q1_executable_file.png" alt="Q1: Malicious EXE" width="50%" height="50%"> <br>

---
<br>

**Q2: When was the last time the malicious executable file was modified? 12-hour format**
> 11/15/2022 09:18:51 PM

Select SysInternals.exe

On the Properties window, see **Date Modified** for the timestamp.

<img src="images/q2_date_modified.png" alt="Q2: EXE date modified" width="35%" height="35%"> <br>

---
<br>

**Q3: What is the SHA1 hash value of the malware?**
> fa1002b02fc5551e075ec44bb4ff9cc13d563dcf

Open Registry Explorer (may need admin privileges).

Navigate to `File -> Load hive`.

Select `[root]\Windows\appcompat\Programs\Amcache.hve`

Expand `InventoryApplicationFile`.

<img src="images/q3_regexplorer_amcache.png" alt="Q3: Registry Explorer - Amcache" width="40%" height="40%"> <br>

Select `Select sysinternals.exe|1a80e611058c98e5`.

See **File Id** for the hash.

<img src="images/q3_regexplorer_sysinternal_hash.png" alt="Q3: Registry Explorer - Sysinternals File Hash" width="40%" height="40%"> <br>

---
<br>

**Q4: What is the malware's family?**
> rozena

Go to VirusTotal and search for the hash from Q3.

Click on the `DETECTION` tab, look at **Family labels**.

<img src="images/q4_vt_family.png" alt="Q4: VirusTotal - File Hash Results" width="75%" height="75%"> <br>

---
<br>

**Q5: What is the first mapped domain's Fully Qualified Domain Name (FQDN)?**
> www.malware430.com

Search for the SHA1 hash in VirusTotal

Click on the `RELATIONS` tab and look under **Contacted Domains**.

<img src="images/q5_vt_relations_domains.png" alt="Q5: VirusTotal - Relations Domains" width="50%" height="50%"> <br>

---
<br>

**Q6: The mapped domain is linked to an IP address. What is that IP address?**
> 192.168.15.10

Navigate to `[root]\Windows\System32\drivers\etc` and open the `hosts` file to find the name and IP mapping.

<img src="images/q6_hosts_file.png" alt="Q6: Hosts file" width="35%" height="35%"> <br>

---
<br>

**Q7: What is the name of the executable dropped by the first-stage executable?**
> vmtoolsIO.exe

An attempt was made to run Strings on the malicious `Sysinternals.exe` but no results came back. In addition, CyberChef also did not find any strings and an upload to VirusTotal came back clean. These outcomes were all unexpected. Luckily, IECacheView was able to locate another copy.

In FTK, right-click on `[root]\Windows\IEUser` and click `Export Files...`

Launch IE Cache View and navigate to `File -> Select Cache Folder`.

Select `\IEUser\AppData\Local\Microsoft\Windows\WebCache` and click **OK**.

<img src="images/q7_iecacheview.png" alt="Q7: IE Cache View for IEUser" width="50%" height="50%"> <br>

Locate and right-click on `SysInternals[1].exe`, then click on Properties to see the **Full Path**.

The file can be found at `\IEUser\AppData\Local\Packages\microsoft.microsoftedge_8wekyb3d8bbwe\AC\#!001\MicrosoftEdge\Cache\WMFWC1O7\SysInternals[1].exe`.

Run Strings on `SysInternals[1].exe`.
```
strings -nobanner \IEUser\AppData\Local\Packages\microsoft.microsoftedge_8wekyb3d8bbwe\AC\#!001\MicrosoftEdge\Cache\WMFWC1O7\SysInternals[1].exe
```

Scroll down a bit to find the reference to `vmtoolsIO.exe`.

<img src="images/q7_strings_sysinternals.png" alt="Q7: Strings output - vmtoolsIO.exe" width="50%" height="50%"> <br>

We can also double check by looking at the AppCompatCache, located in the SYSTEM hive.

Launch RegistryExplorer with admin privileges and navigate to `File -> Load hive`.

Select `[root]\Windows\System32\config\SYSTEM`.

Navigate to `[ROOT]\ControlSet001\Control\Session Manager\AppCompatCache`

In the top right window, select the **AppCompatCache** key.

<img src="images/q7_regexplorer_appcompatcache_key.png" alt="Q7: Registry Explorer - AppCompatCache Registry Key" width="60%" height="60%"> <br>

In the bottom right window, select the **AppCompatCache** tab and sort by **Modified Time**.

Notice that `vmtoolsIO.exe` was run shortly after the malicious SysInternals.

<img src="images/q7_regexplorer_appcompatcache_timestamps.png" alt="Q7: Registry Explorer - vmtoolsIO.exe Timestamp" width="60%" height="60%"> <br>

---
<br>

**Q8: What is the name of the service installed by 2nd stage executable?**
> VMwareIOHelperService

In the Strings output from Q7, we can see the service name referenced by the `net start` and `sc config` commands.

<img src="images/q8_strings_sysinternals.png" alt="Q8: Strings output - VMwareIOHelperService" width="75%" height="75%"> <br>

---
<br>

**Q9: What is the extension of files deleted by the 2nd stage executable?**
> pf

In FTK, right-click on `[root]\Windows\vmtoolsIO.exe` and click `Export Files...`

Run Strings on `vmtoolsIO.exe`.
```
strings -nobanner vmtoolsIO.exe
```

Scroll down to find references to `*.pf` and `C:\Windows\Prefetch`.

<img src="images/q9_strings_vmtools.png" alt="Q9: Strings output - vmtoolsIO Prefetch" width="25%" height="25%"> <br>

In FTK, navigate to `[root]\Windows\PreFetch`.

There is a deleted file named `VMTOOLSIO.EXE-B05FE979.pf` with a timestamp that is close to when the malicious SysInternals and vmtoolsIO were run.

<img src="images/q9_ftk_prefetch.png" alt="Q9: FTK - VMTOOLSIO Prefetch" width="50%" height="50%"> <br>

## References
[Amcache and AppCompatCache](https://andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/)