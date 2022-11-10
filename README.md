# CommonPlace
Common place info dump

## TOC
- TODO

## Quick Commands I Don't Have the Bandwidth to Keep In RAM

### File xfer to locked down Windows hosts over VDI
- On your local machine (with desired exe, script, whatever already downloaded)
```PowerShell
 $base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes('someFilePath'))
 $base64string | clip
 ```
 - On target host
 ```PowerShell
 $data = Get-Clipboard
[IO.File]::WriteAllbytes('someFilePath', [Convert]::FromBase64String($data))
```

### Theoretically get AD users with blank passwords 
- With AD module properly imported and working
```PowerShell
Get-ADUser -Filter * -Properties PasswordLastSet | where-object {($_.PasswordLastSet -eq $null) -and ($_.Enabled -eq 'True')} | ft UserPrincipalName, Created, AccountExpirationDate, CannotChangePassword, Description, LastLogonDate, LockedOut, MemberOf, PasswordNotRequired
```
- Now put users into txt file and use cme to see if you can use any (highly unlikely, but do your due dilligence)
 ```bash
for user in $(cat nopass_users.txt)
do
	crackmapexec smb $someDC -u $user -p ''
done
```
