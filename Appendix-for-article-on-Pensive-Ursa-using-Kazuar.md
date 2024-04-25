# Appendix for "Over the Kazuar’s Nest: Cracking Down on a Freshly Hatched Backdoor Used by Pensive Ursa (aka Turla)"

[Link to article](https://unit42.paloaltonetworks.com/pensive-ursa-uses-upgraded-kazuar-backdoor/)

## Configuration Files Encryption

As documented in Figure 25, one example of the aforementioned directory scheme is where Kazuar saves its individual configuration files. Inside the `config` folder, the malware writes dozens of separate files, each for a different setting.

![Figure 25](https://github.com/PaloAltoNetworks/Unti42-Threat-Intelligence-Article-Information/assets/17553852/6cedfd59-ab5e-4f5c-8842-7be1d93b9c7a)
_Figure 25. Generation of one of the configuration files._

Each such configuration file on disk is encrypted using the XOR algorithm, as shown in Figure 26. This algorithm is also used to encrypt log messages. The messages are encrypted by iterating over an encrypted string and performing an XOR of each byte with a byte from the GUID + the current value of the `J` index.

![Figure 26](https://github.com/PaloAltoNetworks/Unti42-Threat-Intelligence-Article-Information/assets/17553852/b32aba7a-e38f-434c-8a7c-2a1e2090bf3b)
_Figure 26. The XOR algorithm responsible for encrypting log data._

Figure 27 shows that when Kazuar writes a configuration file to disk, it prepends an MD5 hash of the settings key (i.e., `inject`) to the beginning of the file, followed by the aforementioned XOR encrypted content. It later uses this format to validate the correctness of each file by the malware when reading its content.

![Figure 27](https://github.com/PaloAltoNetworks/Unti42-Threat-Intelligence-Article-Information/assets/17553852/82654699-140f-4e47-addc-b98eb1dd62fe)
_Figure 27. Content of an encrypted configuration file, with the `inject` string._

## Log Content Encryption

Kazuar presents a very verbose logging scheme. It creates both logging information for the malware’s execution, and initial reconnaissance gathered from the infected machine. We show a part of its plaintext content in Figure 28.

![Figure 28](https://github.com/PaloAltoNetworks/Unti42-Threat-Intelligence-Article-Information/assets/17553852/d3a4c932-22b2-4fa1-9acc-b4ab722a47d5)
_Figure 28. Snippet of the log file prior to encryption._

Before writing the data into the log file on disk, it is encrypted by performing the aforementioned XOR algorithm that we depicted in Figure 26 above. 

If the main log file is empty, Kazuar uses a hard-coded RSA public key to encrypt the machine’s GUID and writes the RSA encrypted GUID into the beginning of the file. The operators can use this to distinguish among logs sent to the C2 server from different Kazuar agents, and also for integrity checking of the files themselves. 

Figure 29 shows that after the RSA-encrypted GUID, the malware saves the length of the log data in the next 2 bytes, and finally the encrypted logged message itself. This allows the malware to validate, read and decrypt the data easily on-demand.

![Figure 29](https://github.com/PaloAltoNetworks/Unti42-Threat-Intelligence-Article-Information/assets/17553852/390a0ed2-bcc2-4d99-9f6e-4dfe9d6ac083)
_Figure 29. Encrypted content of Kazuar’s main log file RSA encrypted GUID, followed by the data’s length and content._

## The `Forensics` Command

By using the `Forensics` command, the attacker is able to gather additional forensic artifacts from the infected machine. 

These artifacts are as follows:

- **Program Compatibility Assistant** - Programs that the victim configured under the Program Compatibility Assistant (a feature that enables older programs with compatibility issues to work better automatically)
- **The Explorer User Assist registry key** - Kazuar checks for the value of the following registry keys:
  - `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` contains a list of applications, files, links and other objects that have been accessed
  - `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` contains a list of the shortcut links used to start programs
  - `{75048700-EF1F-11D0-9888-006097DEACF9}` contains a list of applications, files, links and other objects that have been accessed
  - `{5E6AB780-7743-11CF-A12B-00AA004AE837}` contains a list of IE Favorites and other IE toolbar objects
- **Prefetch Files** - Provide detailed information about the programs that the victim executed on their computer
- **The MUICache** - Contains data about executables that execute on the system. 
- **`ActivitiesCache.db` file** - Stores information about user activities

## The `Unattend` Command: Cloud and Sensitive Applications Credentials Gathering

- Google Cloud
  - `Gcloud\credentials.db`
  - `Gcloud\legacy_credentials`
  - `Gcloud\access_tokens.db`
- Amazon Web Services
  - `.aws\credentials`
- Microsoft Azure
  - `azure\azureProfile.json`
  - `.azure\TokenCache.dat`
  - `.azure\AzureRMContext.json`
  - `Windows Azure Powershell\TokenCache.dat`
  - `Windows Azure Powershell\AzureRMContext.json`
- IBM Bluemix
  - `Bluemix\config.json`
  - `.bluemix\.cf\config.json`

Additionally the `unattend` command enables the attacker to steal other artifacts. 

- `unattend.xml`, `sysprep.xml` and `sysprep.inf` are used to modify Windows settings during Setup. If these files are not properly sanitized, they can leave administrative credentials in plain text.
- `web.config` is read by IIS and the ASP.NET Core Module to configure an app hosted with IIS. An attacker can use this file for privilege escalation. 
- Keepass passwords
  - `KeePass.config.xml`
  - `ProtectedUserKey.bin`

## The `Steal` Command

- Git SCM
- Signal 
- OpenVPN
- Windows credentials (using the [`CredEnumerateW`](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credenumeratew) winAPI)
- FileZilla
- WinSCP
- Chromium-based browsers
- Mozilla-based browsers
- Internet Explorer
- Outlook

## Logs and Configuration Directory Structure

- `Root directory`
  - `Main log file`
  - `common`
    - `wordlist` (unreferenced file)
  - `logs`
    - `keys` (keylogger file path)
  - `config`
  - `task`
  - `result`
  - `peeps`
  - `autos`
    - `files`
    - `hashes`

## Threads Names and Descriptions

| Thread Name                                      | Description                          |
| ------------------------------------------------ | ------------------------------------ |
| `MIND`                                           | Anti-analysis                        |
| `REMO`                                           | Communication using named pipes      |
| `INJE`                                           | Injection class                      |
| `EVEN`                                           | Event log monitoring                 |
| `PEEP` or `PEEW`                                 | Active window monitoring             |
| `SOLV`                                           | Solve tasks from the C2              |
| `GPCK`, `GHOO`, `GW` + path, `GFIL`, `GINF` or `GMAP` | Autos related working threads   |
| `KEYL`                                           | Key logger                           |
| `SEND`                                           | Communication with the C2 using HTTP |
| `HIND`                                           | WMI consumer class                   |
| `REM*`                                           | Nested remote class                  |
| `SOL*`                                           | Nested solver class                  |

## WMI Consumer `Morphing` Thread

This is one of the threads that the threat operator enabled in Kazuar’s "non-interactive mode." Kazuar has the ability to search WMI event consumers for the ones that have the `ActiveScriptEventConsumer` class active. This class allows a user to run an ActiveX script code whenever the OS delivers an event. Kazaur can edit the script that is configured to be run by the `ActiveScriptEventConsumer` class with a new script, as shown in Figure 30. 

![Figure 30](https://github.com/PaloAltoNetworks/Unti42-Threat-Intelligence-Article-Information/assets/17553852/79784659-9fee-4ea2-8334-54caf6843c41)
_Figure 30. Snippet of code from the ​​WMI Consumer `Morphing` class._

## Anti-Analysis 

### Honeypot Check

If Kazuar found Kaspersky’s honeypot on the machine, it checks if more than five of the following processes or files exist on the machine:

**Process list:**

- Bitcoin-Qt
- Bitcoind
- IExplore
- Firefox
- Infium
- Chrome
- Opera
- Skype
- ICQ
- AIM
- Qip

**Filenames:**

- `Financial_report.xls`
- `Financial_report.ppt`
- `Credit-report.pdf`
- `Accounts.xlsx`
- `Passwords.txt`
- `Invoice.docx`
- `Report.doc`
- `Keys.txt`
- `Пароли.txt` ("passwords" in Russian)
- `Отчёт.rtf` ("report" in Russian)
- `Отчёт.doc` ("report" in Russian)

### Analysis Tools Check

- Immunity Debugger
- Process Explorer
- Process Monitor
- Process Hacker
- SysInspector
- SysAnalyzer
- MegaDumper
- Wireshark
- PE Tools
- Fiddler
- TCPView
- OllyDbg
- WinDbg
- X64dbg
- X32dbg
- DnSpy
- Joeboxcontrol
- Joeboxserver
- Dumpcap

### Sandbox Libraries Check

- `Dir_watch.dll`
- `Cmdvrt32.dll`
- `Sbiedll.dll`
- `Api_log.dll`
- `Pstorec.dll`
- `sxin.dll`

## Auto-Runs Check on the Infected Machine

### Registry (HKCU and HKLM):

- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunService`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceService`
- `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunService`
- `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceService`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
- `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run,`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\VmApplet`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\load`
- `SOFTWARE\Microsoft\Office test\Special\Perf`
- `SOFTWARE\Microsoft\Command Processor\AutoRun`
- `Control Panel\Desktop\SCRNSAVE.EXE`

### WMI Consumers

- `ActiveScriptEventConsumer`
- `CommandLineEventConsumer`

### Environment Variables

- `UserInitMprLogonScript` - Contains configured logon scripts
- `APPDOMAIN_MANAGER_TYPE` and APPDOMAIN_MANAGER_ASM` - used for [AppDomain Manager Injection](https://www.rapid7.com/blog/post/2023/05/05/appdomain-manager-injection-new-techniques-for-red-teams/)
- _`COR_PROFILER_PATH`_ and _`COR_PROFILER`_ - [may be used](https://redcanary.com/blog/cor_profiler-for-persistence/) to load DLLs into .NET processes

## Optional Injected Processes

- IExplore
- Outlook
- Firefox
- Jusched
- Vivaldi
- Browser
- Nlnotes
- MSEdge
- Notes2
- Chrome
- Opera
- Brave

## Hard-Coded Configuration Paths

- `Microsoft\Windows\PowerShell`
- `Microsoft\Office\PowerPoint`
- `Microsoft\Internet Explorer`
- `Microsoft\Office\Publisher`
- `Microsoft\Windows\Explorer`
- `Microsoft\Office\Outlook`
- `Microsoft\Windows\Shell`
- `Microsoft\Office\Access`
- `Microsoft\Office\Visio`
- `Microsoft\Office\Excel`
- `Microsoft\Media Player`
- `Microsoft\Office\Word`
- `Microsoft\VisualStudio`
- `Microsoft\CLR_v2.0_32`
- `Microsoft\CLR_v4.0_32`
- `Microsoft\Powerpoint`
- `Microsoft\Installer`
- `Microsoft\CLR_v2.0`
- `Microsoft\CLR_v4.0`
- `Microsoft\OneDrive`
- `Microsoft\Network`
- `Microsoft\Outlook`
- `Microsoft\MSBuild`
- `Microsoft\Office`
- `Microsoft\DotNet`
- `Microsoft\Access`
- `Microsoft\AddIns`
- `Microsoft\Crypto`
- `Microsoft\Vault`
- `Microsoft\Excel`
- `Mozilla\Firefox`
- `Microsoft\Word`
- `Microsoft`
- `Adobe`

## Comprehensive System Profiling

- Agent configuration
- Operating system information
- Hardware information
- User information
- Logon sessions
- User profiles
- Folders information
- Run command history
- Explorer typed path
- Explorer search history 
- Environment variables
- UAC settings
- Internet settings
- DNS cache
- .NET/PS versions
- WSUS settings
- Installed software
- Hot patches
- System update history
- System services
- System drivers
- Optional OS features
- Security software installed
- AMSI providers
- Security packages
- Applocker settings
- Logical drives
- USB devices
- Network adapters
- Network ARP table
- Network connections
- Network shares
- RDP connections
- Running processes
- Active windows
- Recent open Office documents
- Outlook downloads 
- Recycle bin items
- Screen capture at infection time

## Browser Data

- **Internet Explorer**
- **Chromium Browsers**
  - 7Star Browser
  - Amigo Browser
  - Atom Browser
  - Brave Browser
  - Cent Browser
  - Chedot Browser
  - Chrome Browser
  - Chrome SxS
  - Chromium Browser
  - CocCoc Browser
  - Comodo Browser
  - Elements Browser
  - Epic Browser
  - Kometa Browser
  - Microsoft Edge
  - Opera Browser
  - Opera GX Browser
  - Orbitum Browser
  - Sputnik Browser
  - Torch Browser
  - Uran Browser
  - Vivaldi Browser
  - Yandex Browser
- **Mozilla Browsers**
  - Mozilla Firefox
  - CyberFox Browser
  - Comodo IceDragon
  - Mozilla IceCat
  - K-Meleon Browser
