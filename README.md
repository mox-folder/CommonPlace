# CommonPlace
Common place info dump

## TOC
- File xfer to locked down Windows hosts over VDI
- Theoretically get AD users with blank passwords
- AD delegation checks
- Check PrintSpooler service on windows hosts
- Check for CrestronSSH hosts where default creds are likely (admin:password)

TODO: add anchor links to above

## Quick Commands I Don't Have the Bandwidth to Keep In RAM

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
Get-ADComputer -Filter {TrustedForDelegation -eq $true -or TrustedToAuthForDelegation -eq $true} -Properties trustedfordelegation,trsutedtoauthfordelegation | ft DNSHostName, Name, Enabled, TrustedForDelegation,TrustedToAuthForDelegation

Get-ADUser -Filter {TrustedForDelegation -eq $true -or TrustedToAuthForDelegation -eq $true} -Properties trustedfordelegation,trsutedtoauthfordelegation, | ft Name, Enabled, TrustedForDelegation,TrustedToAuthForDelegation
```

### Check PrintSpooler service on windows hosts
Get a list of hostnames from above delegation checks and use tip from [iredteam](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation) to simply check if the spool service is available
```PowerShell
foreach($host in $hosts){
	$hostname = echo $item.name
	ls \\$hostname\pipe\spoolss
}
```

### Check for CrestronSSH hosts where default creds are likely (admin:password)
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

### Query AD for a list of unique operating systems 
```Powershell
$hosts = Get-ADComputer -filter 'enabled -eq "true"' -Properties Name,OperatingSystem
$hosts | sort Name | select -Unique OperatingSystem
```
