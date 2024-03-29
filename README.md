# CommonPlace
An infodump of commands/knowledge/techniques/tips/tricks/etc. that I don't have the bandwidth to keep in mental RAM.

## [Enumeration & Scanning](#enumeration--scanning)
- [nmap k-scan](#the-mighty-nmap-k-scan)
- [basic fuffery](#basic-fuffery)
- [nuclei](#nuclei)

## [Windows and AD Environments](#windows--ad-environments)
- [File xfer to locked down Windows hosts over VDI](#file-xfer-to-locked-down-windows-hosts-over-vdi)
- [Import AD DLL command order](#import-ad-dll-command-order)
- [Theoretically get AD users w/ blank passwords](#theoretically-get-ad-users-with-blank-passwords)
- [AD Delegation Checks](#ad-delegation-checks)
- [Check PrintSpooler service on Windows hosts](#check-printspooler-service-on-windows-hosts)
- [Query AD for list of unique operating systems](#query-ad-for-a-list-of-unique-operating-systems)
- [SMB File grabbing](#smb-file-grab-one-liner)

## [IOT Hosts - Fun stuff](#iot-hosts)
- [Check for CrestronSSH hosts w/ default creds](#check-for-crestronssh-hosts-where-default-creds-are-likely)

## [Tooling](#tooling)
- [Bloodhound Setup](#bloodhound-setup)

## Enumeration & Scanning

### Nmap scope list to individual IPs (no resolution)
```bash
nmap -sL -iL <scope_list> -n
```

### The mighty nmap k-scan
```bash
nmap -Pn -sT -n -v --top-ports 50 -sV -A -iL some-ip-file.txt --reason --max-retries=2 --min-hostgroup=64 -oX some-ip-file-st-topports-50.xml -v
```
### Basic Fuffery
```bash
ffuf -w /path/to/some/wordlist:FUZZ -u http://some-host.some-domain/FUZZ -rate 5
```
### Nuclei
```bash
nuclei -u http://foobar.com -rl $RATE -o $customTemplates-foobar-dot-com.txt -stats -t ~/$customTemplatesDir/ #use custom templates
nuclei -u http://foobar.com -rl $RATE -o nuclei-foobar-dot-com.txt -stats # use default templates
```

## Windows & AD Environments

### File xfer to locked down Windows hosts over VDI
On your local machine (with desired exe, script, whatever already downloaded)
```PowerShell
 $base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes('someFilePath'))
 $base64string | clip
 ```
On target host
 ```PowerShell
 $data = Get-Clipboard
[IO.File]::WriteAllbytes('someFilePath', [Convert]::FromBase64String($data))
```

### Import AD DLL command order
```PowerShell
Import-module .\Microsoft.ActiveDirectory.Management.dll -Verbose
Import-Module .\ActiveDirectory.psd1
```

### Theoretically get AD users with blank passwords 
With AD module properly imported and working
```PowerShell
Get-ADUser -Filter * -Properties PasswordLastSet | where-object {($_.PasswordLastSet -eq $null) -and ($_.Enabled -eq 'True')} | ft UserPrincipalName, Created, AccountExpirationDate, CannotChangePassword, Description, LastLogonDate, LockedOut, MemberOf, PasswordNotRequired
```
Now put users into txt file and use cme to see if you can use any (highly unlikely, but do your due dilligence)
 ```bash
for user in $(cat nopass_users.txt)
do
	crackmapexec smb $someDC -u $user -p ''
done
```

### AD Delegation checks
```PowerShell
Get-ADComputer -Filter {TrustedForDelegation -eq $true -or TrustedToAuthForDelegation -eq $true} -Properties trustedfordelegation,trustedtoauthfordelegation | ft DNSHostName, Name, Enabled, TrustedForDelegation,TrustedToAuthForDelegation

Get-ADUser -Filter {TrustedForDelegation -eq $true -or TrustedToAuthForDelegation -eq $true} -Properties trustedfordelegation,trustedtoauthfordelegation, | ft Name, Enabled, TrustedForDelegation,TrustedToAuthForDelegation
```

### Check PrintSpooler service on windows hosts
Get a list of hostnames from above delegation checks and use tip from [iredteam](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation) to simply check if the spool service is available
```PowerShell
foreach($host in $hosts){
	$hostname = echo $item.name
	ls \\$hostname\pipe\spoolss
}
```

### Query AD for a list of unique operating systems 
```Powershell
$hosts = Get-ADComputer -filter 'enabled -eq "true"' -Properties Name,OperatingSystem
$hosts | sort Name | select -Unique OperatingSystem

# alternate one-liner
Get-ADComputer -Filter "enabled -eq 'true'" -Properties operatingSystem | group -Property operatingSystem | Select Name,Count | Sort Name | ft -AutoSize
```

### smb file grab one liner
	`smbclient '\\HOST\DRIVE$' -c 'prompt OFF;recurse ON;lcd "C";mget *' -u "$USER"`
 
## IOT Hosts

### Check for CrestronSSH hosts where default creds are likely
Note these use this cred pair: (admin:password)
```Bash
#!/bin/bash
# expects output from msfconsole command `services -S 'CrestronSSH' -o crestron_ssh_hosts.txt` <- could also be worth just checking any 22 port
# cat crestron_ssh_hosts.txt | cut -d ',' -f 1 | tr -d '"' | tail -n +2 > crestron_hosts.txt <- to build
touch tmp_responses.txt
touch tmp_output.txt
totalHosts=$(wc -l crestron_hosts.txt | cut -d " " -f 1)
echo "Total Hosts to Check: $totalHosts"
for host in $(cat crestron_hosts.txt)
do
	echo '\r\n' | nc -nv $host 22 > tmp_responses.txt
	response=$(cat tmp_responses.txt | awk 'FNR==1' | tr -d '\r')
	if [[ "$response" =~ .*"Crestron".* ]]; then
		echo "$host = crestron" >> tmp_output.txt
	fi
done
crestronCount=$(wc -l tmp_output.txt | cut -d " " -f 1)
cat tmp_output
echo "$crestronCount of $totalHosts checked are Crestrons..."
rm tmp_output.txt
rm tmp_responses.txt
```
## Bloodhound Setup
```
sudo apt-get install openjdk-11-jdk

wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable 4' | sudo tee /etc/apt/sources.list.d/neo4j.list > /dev/null
sudo apt-get update

sudo apt-get install apt-transport-https

sudo apt-get install neo4j
sudo systemctl stop neo4j
cd /usr/bin
sudo ./neo4j console
sudo systemctl start neo4j
wget https://github.com/BloodHoundAD/BloodHound/releases/download/v4.3.1/BloodHound-linux-x64.zip
unzip BloodHound-linux-x64
cd BloodHound-Linux-x64
./BloodHound --no-sandbox
```
