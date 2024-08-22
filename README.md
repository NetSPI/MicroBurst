![MicroBurstLogo](https://notpayloads.blob.core.windows.net/images/Microburst_Github.png) 
<br> 
[![licence badge]][licence] 
[![stars badge]][stars] 
[![forks badge]][forks] 
[![issues badge]][issues]
![Twitter Follow](https://img.shields.io/twitter/follow/kfosaaen.svg?style=social)


[licence badge]:https://img.shields.io/badge/license-New%20BSD-blue.svg
[stars badge]:https://img.shields.io/github/stars/NetSPI/MicroBurst.svg
[forks badge]:https://img.shields.io/github/forks/NetSPI/MicroBurst.svg
[issues badge]:https://img.shields.io/github/issues/NetSPI/MicroBurst.svg


[licence]:https://github.com/NetSPI/MicroBurst/blob/master/LICENSE.txt
[stars]:https://github.com/NetSPI/MicroBurst/stargazers
[forks]:https://github.com/NetSPI/MicroBurst/network
[issues]:https://github.com/NetSPI/MicroBurst/issues


### MicroBurst: A PowerShell Toolkit for Attacking Azure

MicroBurst includes functions and scripts that support Azure Services discovery, weak configuration auditing, and post exploitation actions such as credential dumping. It is intended to be used during penetration tests where Azure is in use.

### Author, Contributors, and License
* Author: Karl Fosaaen ([@kfosaaen](https://twitter.com/kfosaaen)), NetSPI
* Contributors: 
	* Scott Sutherland ([@_nullbind](https://twitter.com/_nullbind))
	* Thomas Elling ([@thomaselling](https://twitter.com/thomas_elling))
	* Jake Karnes ([@jakekarnes42](https://twitter.com/jakekarnes42))
	* Josh Magri ([@passthehashbrwn](https://twitter.com/passthehashbrwn))
* License: BSD 3-Clause
* Required Dependencies: Az, Azure, AzureRM, AzureAD, and MSOnline PowerShell Modules are all used in different scripts
* Dependencies Note: Originally written with the AzureRM PS modules, older scripts have been ported to their newer Az equivalents
* Platform Note: These scripts will only run on a Windows-based platform.

### Importing the Module / Usage
	PS C:> Import-Module .\MicroBurst.psm1
This will import all applicable functions based off of the currently installed modules in your environment. The scripts can then be invoked using their names like
```
PS C:> Get-AzDomainInfo
```

If you want to simplify the trusting of the code files, use the following "Unblock-File" command to recursively trust each of the downloaded files:

	PS C:> dir -Recurse .\MicroBurst-master | Unblock-File

Recommended Modules to install:
* <a href="https://docs.microsoft.com/en-us/powershell/azure/new-azureps-module-az?view=azps-3.6.1">Az</a>
* <a href="https://docs.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0">AzureAd</a>
* <a href="https://docs.microsoft.com/en-us/powershell/module/msonline/?view=azureadps-1.0">MSOnline</a>

Here's how a module can be installed in Powershell
```
PS C:> Install-Module <module-name>
```
### Scripts Information
If you want to learn what a specific script does use `Get-Help` with script name like:
```
PS C:> Get-Help Invoke-EnumerateAzureSubDomains
```

### Related Blogs
* <a href="https://blog.netspi.com/a-beginners-guide-to-gathering-azure-passwords/">A Beginners Guide to Gathering Azure Passwords</a>
* <a href="https://blog.netspi.com/enumerating-azure-services/">Anonymously Enumerating Azure Services</a>
* <a href="https://blog.netspi.com/anonymously-enumerating-azure-file-resources/">Anonymously Enumerating Azure File Resources</a>
* <a href="https://blog.netspi.com/exporting-azure-runas-certificates/">Get-AzurePasswords: Exporting Azure RunAs Certificates for Persistence</a>
* <a href="https://blog.netspi.com/azure-automation-accounts-key-stores">Using Azure Automation Accounts to Access Key Vaults</a>
* <a href="https://blog.netspi.com/running-powershell-scripts-on-azure-vms">Running PowerShell on Azure VMs at Scale</a>
* <a href="https://blog.netspi.com/maintaining-azure-persistence-via-automation-accounts/">Maintaining Azure Persistence via Automation Accounts</a>
* <a href="https://blog.netspi.com/decrypting-azure-vm-extension-settings-with-get-azurevmextensionsettings/">Decrypting Azure VM Extension Settings with Get-AzureVMExtensionSettings</a>
* <a href="https://blog.netspi.com/attacking-azure-with-custom-script-extensions/">Attacking Azure with Custom Script Extensions</a>
* <a href="https://blog.netspi.com/lateral-movement-azure-app-services/">Lateral Movement in Azure App Services</a>
* <a href="https://blog.netspi.com/encrypting-password-data-in-get-azpasswords/">Get-AzPasswords: Encrypting Automation Password Data</a>
* <a href="https://blog.netspi.com/azure-privilege-escalation-using-managed-identities/">Azure Privilege Escalation Using Managed Identities</a>
* <a href="https://www.netspi.com/blog/technical/cloud-penetration-testing/azure-persistence-with-desired-state-configurations/">Azure Persistence with Desired State Configurations</a>
* <a href="https://www.netspi.com/blog/technical/cloud-penetration-testing/extract-credentials-from-azure-kubernetes-service/">How To Extract Credentials from Azure Kubernetes Service (AKS)</a>
* <a href="https://www.netspi.com/blog/technical-blog/cloud-pentesting/extracting-managed-identity-certificates-from-azure-arc-service/">Extracting Managed Identity Certificates from the Azure Arc Service</a>

### Presentations
* <a href="https://youtu.be/CUTwkuiRgqg">Extracting all the Azure Passwords - DEF CON 29 - Cloud Village</a>
  - <a href="https://notpayloads.blob.core.windows.net/slides/ExtractingalltheAzurePasswords.pdf">Slides</a>
* <a href="https://www.youtube.com/watch?v=EYtw-XPml0w">Adventures in Azure Privilege Escalation - DerbyCon 9</a>
  - <a href="https://notpayloads.blob.core.windows.net/slides/Azure-PrivEsc-DerbyCon9.pdf">DerbyCon 9 (2019) Slides</a>
* <a href="https://www.youtube.com/watch?v=IdORwgxDpkw">Attacking Azure Environments with PowerShell - DerbyCon 8</a>
  - <a href="https://www.slideshare.net/kfosaaen/derbycon-8-attacking-azure-environments-with-powershell">DerbyCon 8 (2018) Slides</a>
  - <a href="https://www.slideshare.net/kfosaaen/bsides-portland-attacking-azure-environments-with-powershell">BSidesPDX (2018) Slides</a>
	
### Wiki Information
Check out the [MicroBurst Wiki](https://github.com/NetSPI/MicroBurst/wiki) for more information on the usage of the toolkit and the available functions.
