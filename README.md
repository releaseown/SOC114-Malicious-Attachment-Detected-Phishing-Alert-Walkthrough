# SOC114 – Malicious Attachment Detected – Phishing Alert

## Introduction

This walkthrough examines the primary email artifacts and Indicators of Compromise (IOCs).

The content is intended to help cybersecurity professionals and students who are working through this lab.

## Incident Identification

Before starting the technical analysis, record the alert's key metadata. These values are used to locate the incident in the LetsDefend Email Security view.

Key event details:

- **Event ID:** 45
- **Date:** Jan 31, 2021 – 03:48 PM
- **Source address:** `accountingcmail.carleton.ca`
- **Destination address:** `richard@letsdefend.io`
- **SMTP address:** `49.234.43.39`

- **Email subject:** Invoice

These fields are essential during initial triage: using the **Event ID** or the sender/recipient combination lets you quickly open the correct alert and ensure the investigation focuses on the right incident.

Once the alert is located in the **Email Security** view, proceed to a detailed analysis of the message body and the attached file.

![5B89D6D8-EA6A-4215-A7F2-5055EC10BB46.png](imgs/5B89D6D8-EA6A-4215-A7F2-5055EC10BB46.png)

- In real SOC environments, correct event identification prevents duplicate or misdirected analysis, saving time and reducing operational errors.

## Locating the Email in the Platform

Using the **source address** (`accounting@cmail.carleton.ca`) as the search criterion in the **Email Security** view quickly located the event for **Event ID 45**, ensuring the analysis targeted the correct incident.

![EBA534ED-5766-4E97-89FC-A18662870133.png](imgs/EBA534ED-5766-4E97-89FC-A18662870133.png)

## Downloading the Attached File

Inside the email details, an **attached file** was identified:

- **File name:** `c9ad9506bcccfaa987ff9fc11b91698d`
- **Archive password:** `infected`

Important: the download and handling of this sample were performed exclusively in a controlled lab environment following malware analysis best practices. Do not run it on your workstation.

![E391F8E6-3CBA-4D36-85A4-116434A6AA8B.png](imgs/E391F8E6-3CBA-4D36-85A4-116434A6AA8B.png)

Clicking “submit” redirected to a password-protected download page. After entering the password **infected**, the file became available for download.

Password-protected archives are commonly used to evade detection by security gateways and antivirus engines.

![D6F52020-95B8-4A2B-8465-782841D8C8FB.png](imgs/D6F52020-95B8-4A2B-8465-782841D8C8FB.png)

## Initial File Inspection

After download, the operating system displayed a warning that the file may be malicious, reinforcing the need for cautious analysis.

File properties confirmed the sample was a ZIP archive of approximately 2.1 MB.

These characteristics align with attachments used in malware delivery via phishing or spear-phishing and warrant deeper inspection of the archive contents.

Password-protected ZIPs are often used to bypass automated inspection and increase campaign success rates.

## File Analysis with Filescan.io

After identifying and downloading the archive, the next step was to analyze its contents with Filescan.io, a platform for static and dynamic inspection of suspicious files.

![D68D0018-9D2D-4B7A-8F1A-2858ED90CA80.png](imgs/D68D0018-9D2D-4B7A-8F1A-2858ED90CA80.png)

Filescan.io reported the archive contained a Microsoft Excel document (.xlsx) with the following SHA-256 hash:

- **SHA-256:**

	`44e65a641fb970031c5efed324676b5018803e0a768608d3e186152102615795`

- **Contained file:**

	`44e65a641fb970031c5efed324676b5018803e0a768608d3e186152102615795.xlsx`

Filescan.io automatically classified the file as a threat, reporting artifacts and behaviors consistent with malicious execution observed in static analysis and emulation.

## Filescan.io – Overview

Using a Microsoft Office (Excel) document as the initial infection vector matches common patterns in targeted phishing campaigns, where attackers leverage user trust and legitimate Office features to achieve code execution on the endpoint. This aligns with MITRE ATT&CK technique Initial Access – Phishing: Attachment (T1566.001).

Reference: https://attack.mitre.org/techniques/T1566/001

![5CE3039D-08B8-49DE-AFAA-8A3F94FCC422.png](imgs/5CE3039D-08B8-49DE-AFAA-8A3F94FCC422.png)

## Office Document Exploitation

There is clear evidence of exploitation within the Office document.

The presence of EMBED.Equation objects strongly indicates abuse of the Equation Editor, a historical exploitation vector used to achieve arbitrary code execution (related to MITRE technique T1203).

Additionally, DLL load events observed during emulation show the document attempts to execute additional code on the victim system, indicating an early-stage execution flow.

These findings suggest the Excel file does not rely solely on traditional VBA macros, but uses alternative execution techniques that can bypass macro-only detection controls.

## External Executable Download and C2 (Command and Control)

During emulation, a critical Command and Control (C2) indicator was observed: an attempt to download an external Windows executable from attacker-controlled infrastructure.

![F9C37EEA-3BC0-4419-AC02-57FF970E2CA6.png](imgs/F9C37EEA-3BC0-4419-AC02-57FF970E2CA6.png)

The identified URL ends with **.exe**, indicating a downloader/dropper stage attempting to fetch a Windows executable.

Associated URL:

> http://andaluciabeach.net/image/network.exe

![732697D4-0485-4AB0-A0EF-9CB53E9588E9.png](imgs/732697D4-0485-4AB0-A0EF-9CB53E9588E9.png)

- **Program:** excel

Command used to open the sample in the emulator:

```jsx
"%PROGRAMFILES%\Microsoft Office 2010\Office14\excel.exe" C:\44e65a641fb970031c5efed324676b5018803e0a768608d3e186152102615795.xlsx
```

Searching Endpoint Security for the associated URL returns C2 search hits with a command line referencing Excel (C:/Program Files/Microsoft Office/Office14/EXCEL.EXE), which is used to open the document and trigger the dropper.

![image.png](imgs/image.png)

### VirusTotal and Threat Intelligence

To validate and enrich the analysis, the archive and its contents were submitted to VirusTotal for correlation across multiple antivirus engines, collaborative rules (YARA/Sigma), and OSINT sources.

![11BD258B-642A-485A-8533-8FD8918340A7.png](imgs/11BD258B-642A-485A-8533-8FD8918340A7.png)

### Overall VirusTotal Classification

The file was widely recognized as malicious:

- **Detections:** 35/62
- **Predominant classification:** Trojan
- **Analyzed file (SHA-256):**

	`44e65a641fb970031c5efed324676b5018803e0a768608d3e186152102615795`

- **File name:**

	`44e65a641fb970031c5efed324676b5018803e0a768608d3e186152102615795.xlsx`

This detection rate indicates strong vendor consensus and reduces the likelihood of a false positive, reinforcing the sample's malicious nature.

![3de2d5a6-fb38-49a2-9e06-961a3c42c408.png](imgs/3de2d5a6-fb38-49a2-9e06-961a3c42c408.png)

## Correlation with Filescan.io

VirusTotal results corroborate Filescan.io findings, which classified the sample as:

- **Verdict:** MALICIOUS
- **Confidence:** 100/100

### Relevant tags identified:

- embedequation
- exploit
- shellcode
- lolbin
- vbc
- ooxml

# Case Closure – LetsDefend

When performing the SOC114 lab (“Malicious Attachment Detected – Phishing Alert”), the following questions were asked as part of the incident investigation:

- **When was it sent?**

	Jan 31, 2021 – 03:48 PM

- **What is the email's SMTP address?**

	`49.234.43.39`

- **What is the sender address?**

	`accounting@cmail.carleton.ca`

- **What is the recipient address?**

	`richard@letsdefend.io`

- **Is the mail content suspicious?**

	Yes

- **Are there any attachments?**

	Yes

Based on the full analysis—including email inspection, attachment analysis, associated infrastructure, and OSINT correlation—all lab questions were answered correctly, confirming the classification as phishing with a malicious attachment.

This document aims to demonstrate analytical reasoning, investigation workflow, and SOC best practices rather than only providing final answers.

I hope this walkthrough helped you solve the challenge. Answers were deliberately not highlighted to encourage hands-on practice and artifact exploration.

![5B17E63B-2DD5-4DD8-95AF-55D0D2921C49.png](imgs/5B17E63B-2DD5-4DD8-95AF-55D0D2921C49.png)

## Case Summary

This walkthrough presented a complete analysis of a phishing incident with a malicious attachment from the LetsDefend SOC114 lab. The investigation followed a typical SOC workflow from alert identification to technical threat validation.

The email contained a password-protected archive whose internal content was a malicious Microsoft Excel document designed to exploit Office features and act as a dropper for later stages of the infection.

Correlation between static/emulation analysis (Filescan.io), vendor detection and reputation (VirusTotal), collaborative rules (YARA/Sigma), and external infrastructure allowed us to confidently classify the incident as phishing with malware delivery, involving Initial Access, Execution, Defense Evasion, and Command and Control techniques per MITRE ATT&CK.

This case highlights the value of structured, evidence-based analysis and the continued prevalence of Office attachments as an attack vector.

## TTP Mapping – MITRE ATT&CK

Based on email and attachment analysis, emulation, and infrastructure correlation, the following Tactics, Techniques, and Procedures (TTPs) were identified:

### Initial Access

**T1566.001 – Phishing: Attachment**

The initial vector was a phishing email containing a malicious attachment. The archive's password protection reinforces attempts to evade detection.

---

### Execution

**T1204.002 – User Execution: Malicious File**

Execution relies on user interaction (opening the attached Excel file).

**T1059.005 – Command and Scripting Interpreter: Visual Basic**

Emulation showed evidence of VBA/VBC usage for code execution.

**T1106 – Native API**

The file uses native Windows APIs for process execution and dynamic library loading, as observed in emulation outputs.

---

### Defense Evasion

**T1027 – Obfuscated/Encrypted File or Information**

The Office document is encrypted/password-protected, a common technique to hinder inspection.

**T1218 – Signed Binary Proxy Execution (LoLBins)**

Indicators of Living-off-the-Land Binaries (LoLBins) were observed, where legitimate system utilities are leveraged for malicious execution.

---

### Command and Control

**T1105 – Ingress Tool Transfer**

Emulation captured an attempt to download an additional payload from external infrastructure:

> http://andaluciabeach.net/image/network.exe

This indicates attacker-controlled tool transfer into the compromised environment.

**T1071.001 – Application Layer Protocol: Web Protocols (HTTP)**

Observed communication used HTTP, a common application-layer protocol for C2.

---

### Discovery

**T1082 – System Information Discovery** *(indicated)*

API calls and general behaviors observed in emulation suggest initial system reconnaissance actions are possible after payload execution.

---

## Remediation Recommendations

### YARA Rule (example)

```jsx
rule autogen_xlsx_EmbedequationEvasiveExploitLolbinShellcodeVbc_44e65a64
{
	meta:
		author = "FileScan.IO Engine v1.1.0-634de8c"
		date = "2026-01-03"
		sample = "44e65a641fb970031c5efed324676b5018803e0a768608d3e186152102615795"
		score = 100
		tags = "embedequation,evasive,exploit,lolbin,shellcode,vbc"
		isWeakRule = true

	strings:
		$magicBytes = {D0 CF 11 E0 A1 B1 1A E1}

		//IOC patterns
		$req0 = "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}N"

		//optional strings
		$opt0 = "EncryptedPackage"
		$opt1 = "EncryptionInfo"
		$opt2 = "Microsoft Enhanced RSA and AES Cryptographic Provider"
		$opt3 = "StrongEncryptionDataSpace"
		$opt4 = "StrongEncryptionTransform"

	condition:
		//require 75% of optional strings
		$magicBytes at 0 and filesize > 1996647 and filesize < 2440345 and all of ($req*) and 3 of ($opt*)
}
```

## **Indicators of Compromise (IOCs)**

The Indicators of Compromise (IOCs) are extracted from the analyzed binary or from artifacts derived during analysis (for example, extracted files). Indicators with a high likelihood of representing a genuine IOC are marked as **interesting**.

**Urls** 

| **IOC** | **Prevalence** | **OSINT** | **Verdict** |
| --- | --- | --- | --- |
| http://andaluciabeach.net/image/network.exe | [1](https://www.filescan.io/search-result?query=aHR0cDovL2FuZGFsdWNpYWJlYWNoLm5ldC9pbWFnZS9uZXR3b3JrLmV4ZQ%3D%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&age=7)[1](https://www.filescan.io/search-result?query=aHR0cDovL2FuZGFsdWNpYWJlYWNoLm5ldC9pbWFnZS9uZXR3b3JrLmV4ZQ%3D%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&verdict_groups=malicious%2Clikely_malicious&age=7) | **CL** | Compromised |
| **Origin:** VBA emulation |  |  |  |

**Domains**

| **IOC** | **Prevalence** | **Verdict** |
| --- | --- | --- |
| andaluciabeach.net | [1](https://www.filescan.io/search-result?domain=andaluciabeach.net&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&age=7)[1](https://www.filescan.io/search-result?domain=andaluciabeach.net&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&verdict_groups=malicious%2Clikely_malicious&age=7) | Compromised |
| **Origin:** VBA emulation |  |  |

**IPs**

| **IOC** | **Location** | **For domain** | **Prevalence** | **OSINT** | **Verdict** |
| --- | --- | --- | --- | --- | --- |
| 70.38.21.234 | - | resolução de DNS | [1](https://www.filescan.io/search-result?query=NzAuMzguMjEuMjM0&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&age=7)[1](https://www.filescan.io/search-result?query=NzAuMzguMjEuMjM0&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&verdict_groups=malicious%2Clikely_malicious&age=7) | **U** | Compromised |
| **Origin:** Domain resolve |  |  |  |  |  |
| andaluciabeach.net | [Canada, Montreal](https://www.filescan.io/#0) | - | [1](https://www.filescan.io/search-result?query=YW5kYWx1Y2lhYmVhY2gubmV0&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&age=7)[1](https://www.filescan.io/search-result?query=YW5kYWx1Y2lhYmVhY2gubmV0&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&verdict_groups=malicious%2Clikely_malicious&age=7) |  | Compromised |
| **Origin:** VBA emulation |  |  |  |  |  |

**MD5**

| 59f49d53c17e600ddb0d713ca0394372 | [1](https://www.filescan.io/search-result?query=NTlmNDlkNTNjMTdlNjAwZGRiMGQ3MTNjYTAzOTQzNzI%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&age=7)[1](https://www.filescan.io/search-result?query=NTlmNDlkNTNjMTdlNjAwZGRiMGQ3MTNjYTAzOTQzNzI%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&verdict_groups=malicious%2Clikely_malicious&age=7) | Compromised |
| --- | --- | --- |
| **Origin:** VBA emulation |  |  |
| 39519ab341387a816870ac9bfa4fc5de | [1](https://www.filescan.io/search-result?query=Mzk1MTlhYjM0MTM4N2E4MTY4NzBhYzliZmE0ZmM1ZGU%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&age=7)[1](https://www.filescan.io/search-result?query=Mzk1MTlhYjM0MTM4N2E4MTY4NzBhYzliZmE0ZmM1ZGU%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&verdict_groups=malicious%2Clikely_malicious&age=7) | Compromised |
| 3eb758fd53cd227f6736fd7108166e2d | [1](https://www.filescan.io/search-result?query=M2ViNzU4ZmQ1M2NkMjI3ZjY3MzZmZDcxMDgxNjZlMmQ%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&age=7)[1](https://www.filescan.io/search-result?query=M2ViNzU4ZmQ1M2NkMjI3ZjY3MzZmZDcxMDgxNjZlMmQ%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&verdict_groups=malicious%2Clikely_malicious&age=7) | Compromised |

**SHA1**

| **IOC** | **Prevalence** | **Verdict** |
| --- | --- | --- |
| f31fcc280c08ff4b52f98fa0ad39a41b8bf55fd7 | [1](https://www.filescan.io/search-result?query=ZjMxZmNjMjgwYzA4ZmY0YjUyZjk4ZmEwYWQzOWE0MWI4YmY1NWZkNw%3D%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&age=7)[1](https://www.filescan.io/search-result?query=ZjMxZmNjMjgwYzA4ZmY0YjUyZjk4ZmEwYWQzOWE0MWI4YmY1NWZkNw%3D%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&verdict_groups=malicious%2Clikely_malicious&age=7) | Compromised |
| **Origin:** VBA emulation |  |  |
| 015fc813fe78118f3aa73978abe78eb893f9b4df | [1](https://www.filescan.io/search-result?query=MDE1ZmM4MTNmZTc4MTE4ZjNhYTczOTc4YWJlNzhlYjg5M2Y5YjRkZg%3D%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&age=7)[1](https://www.filescan.io/search-result?query=MDE1ZmM4MTNmZTc4MTE4ZjNhYTczOTc4YWJlNzhlYjg5M2Y5YjRkZg%3D%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&verdict_groups=malicious%2Clikely_malicious&age=7) | Compromised |
| d76c78f497c799ed072a061f53bb19f3a381f475 | [1](https://www.filescan.io/search-result?query=ZDc2Yzc4ZjQ5N2M3OTllZDA3MmEwNjFmNTNiYjE5ZjNhMzgxZjQ3NQ%3D%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&age=7)[1](https://www.filescan.io/search-result?query=ZDc2Yzc4ZjQ5N2M3OTllZDA3MmEwNjFmNTNiYjE5ZjNhMzgxZjQ3NQ%3D%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&verdict_groups=malicious%2Clikely_malicious&age=7) | Compromised |

**SHA-256**

| **IOC** | **Prevalence** | **Verdict** |
| --- | --- | --- |
| 678012ef01aa26aea36b3326cea32e1ec7e3c6072bd7a68fe4b5ec8453cd8bbd | [1](https://www.filescan.io/search-result?query=Njc4MDEyZWYwMWFhMjZhZWEzNmIzMzI2Y2VhMzJlMWVjN2UzYzYwNzJiZDdhNjhmZTRiNWVjODQ1M2NkOGJiZA%3D%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&age=7)[1](https://www.filescan.io/search-result?query=Njc4MDEyZWYwMWFhMjZhZWEzNmIzMzI2Y2VhMzJlMWVjN2UzYzYwNzJiZDdhNjhmZTRiNWVjODQ1M2NkOGJiZA%3D%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&verdict_groups=malicious%2Clikely_malicious&age=7) | Compromised |
| **Origin:** VBA emulation |  |  |
| 56b1edecc9a282a9faafd95d4d9844608b1ae5ccc8731f34f8b30b3825734974 | [1](https://www.filescan.io/search-result?query=NTZiMWVkZWNjOWEyODJhOWZhYWZkOTVkNGQ5ODQ0NjA4YjFhZTVjY2M4NzMxZjM0ZjhiMzBiMzgyNTczNDk3NA%3D%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&age=7)[1](https://www.filescan.io/search-result?query=NTZiMWVkZWNjOWEyODJhOWZhYWZkOTVkNGQ5ODQ0NjA4YjFhZTVjY2M4NzMxZjM0ZjhiMzBiMzgyNTczNDk3NA%3D%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&verdict_groups=malicious%2Clikely_malicious&age=7) | Compromised |
| 9dc437b0afac437902c55cb4c3b12298f8e46bfc052b171c079f91c92f17b6e5 | [1](https://www.filescan.io/search-result?query=OWRjNDM3YjBhZmFjNDM3OTAyYzU1Y2I0YzNiMTIyOThmOGU0NmJmYzA1MmIxNzFjMDc5ZjkxYzkyZjE3YjZlNQ%3D%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&age=7)[1](https://www.filescan.io/search-result?query=OWRjNDM3YjBhZmFjNDM3OTAyYzU1Y2I0YzNiMTIyOThmOGU0NmJmYzA1MmIxNzFjMDc5ZjkxYzkyZjE3YjZlNQ%3D%3D&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&verdict_groups=malicious%2Clikely_malicious&age=7) | Compromised |

**UUIDs**

| **IOC** | **Prevalence** | **Verdict** |
| --- | --- | --- |
| FF9A3F03-56EF-4613-BDD5-5A41C1D07246 | [1](https://www.filescan.io/search-result?uuid=FF9A3F03-56EF-4613-BDD5-5A41C1D07246&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&age=7)[1](https://www.filescan.io/search-result?uuid=FF9A3F03-56EF-4613-BDD5-5A41C1D07246&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&verdict_groups=malicious%2Clikely_malicious&age=7) | Compromised |
| **Origin:** Input file |  |  |
| 0002CE02-0000-0000-C000-000000000046 | [6](https://www.filescan.io/search-result?uuid=0002CE02-0000-0000-C000-000000000046&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&age=7)[6](https://www.filescan.io/search-result?uuid=0002CE02-0000-0000-C000-000000000046&exclude=12bf808d-fc81-41b1-b266-ab782f6f76ec&verdict_groups=malicious%2Clikely_malicious&age=7) | Compromised |
| **Origin:** VBA emulation |  |  |

## Research

- https://www.virustotal.com/graph/g99455b19762447ff8f9e2c2345f3981bcef55a575a1a49eeb92f7a99536dda25
- https://www.virustotal.com/gui/file/44e65a641fb970031c5efed324676b5018803e0a768608d3e186152102615795/detection
- https://attack.mitre.org/techniques/T1566/001/
- https://www.filescan.io/uploads/6959879c8d1aa9829e29c8dd/reports/12bf808d-fc81-41b1-b266-ab782f6f76ec/overview