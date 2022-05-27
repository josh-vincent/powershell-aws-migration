# **Instructions**

Create the following prior to migration 
- Create Local User
- Install AWS Certificates
- AWS SSM
- AWS CLi v2
- AWS Migration Agent

## Dependencies
Download all the dependencies to a shared location `server001`
- AWSCLIV2 
- AWS SSM
- AWS CERTIFICATE

#Create Local User
Create a local user and add it to the administrator's group.
```powershell
    $password = (ConvertTo-SecureString -AsPlainText -Force 'LOCAL-PASSWORD-HERE')
    $localUser = (Get-LocalUser -Name 'localusername' -ErrorAction SilentlyContinue)
    
    if(!$localUser) {
        New-LocalUser -AccountNeverExpires:$true -Password $password -Name 'localusername' `
      | Add-LocalGroupMember -Group 'Administrators'
    } else {
        Write-host "Local User Already Exists" -ForegroundColor DarkYellow
    }
```

# Install AWS Certificate

Copy the AWS certificate from `\\SERVERSHARE\C$\TEMP\AWS\` and store it in C:/TEMP on the local machine
```powershell
$AWSCERT = (Get-ChildItem Cert:\LocalMachine\AuthRoot\* | Where {$_.Subject -match "Amazon Root CA"}) -ne $null

if($AWSCERT -eq $false) {
    Import-Certificate -FilePath "C:/temp/AmazonRootCA1.cer" -CertStoreLocation Cert:\LocalMachine\AuthRoot
} else {
    Write-host "Certificate Already Exists" -ForegroundColor DarkYellow
}
```

# Install AWS SSM

Copy the AWS SSM Agent from `\\SERVERSHARE\C$\TEMP\AWS\` and store it in `C:/TEMP` on the local machine

```powershell
$AWSSSM = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.Displayname -match "AWS SSM"}) -ne $null

if($AWSSSM -eq $false) {
    Write-host "Installing SSM Agent"
    
    $progressPreference = 'silentlyContinue'
    Invoke-WebRequest `
        https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe `
        -OutFile $env:USERPROFILE\Desktop\SSMAgent_latest.exe
    
    Start-Process `
        -FilePath $env:USERPROFILE\Desktop\SSMAgent_latest.exe `
        -ArgumentList "/S"
    
    rm -Force $env:USERPROFILE\Desktop\SSMAgent_latest.exe
    
} else {
    Write-host "AWS SSM AGENT Already Exists" -ForegroundColor DarkYellow
}
```

# Install AWS CLI

Copy the AWS CLI from `\\SERVERSHARE\C$\TEMP\AWS\` and store it in `C:/TEMP` on the local machine
```powershell
$AWSCLI = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.Displayname -match "AWS Command Line Interface v2"}) -ne $null

if($AWSCLI -eq $false) {
    Write-host "Installing AWS CLI"
    Start-Process -Wait -FilePath msiexec -ArgumentList /i, "$(C:\Temp\AWSCLIV2.msi", /qn
} else {
    Write-host "AWS CLI Already Exists" -ForegroundColor DarkYellow
}
```

# AWS Migration Agent
Copy the AwsReplicationWindowsInstaller from `\\SERVERSHARE\C$\TEMP\AWS\` and store it in `C:/TEMP` on the local machine

Get credentials for the account from AWS IAM Users eg. `MIGRATIONGN-AGENT-INSTALLER`
```shell
.\AwsReplicationWindowsInstaller.exe --region us-east-1 --aws-access-key-id PUBLIC-KEY-ID --aws-secret-access-key SECRET-KEY-FOR-ACCOUNT --no-prompt
```

## Powershell to do multiple servers at once

Create a text document at `C:\temp\migrateServerList.txt`

```powershell 
$servers = Get-Content C:\temp\migrateServerList.txt
$credentials = Get-Credential # domain\username

$domain = 'yourdomain.int' # yourdomain.int | yourotherdomain.int
$jumphost = 'server001'
if($domain -like 'yourdomain') { $jumphost = 'SERVERSHARE'}

$Array = @() # Results stored here

foreach($server in $servers) {
    $Row = "" | Select-Object Server, LocalUser, CERT, Cli, SSM
    $Row.Server = $server
    
    Write-Host "$($server) ================================="
    Copy-Item -Path \\$jumphost\c$\temp\AWS\* -Destination \\$server\c$\temp\ -PassThru
    
    $serverResult = Invoke-Command -ComputerName $server -Credential $credentials -ScriptBlock {
    $Results = New-Object PSObject -Property @{
        LocalUser = 'false'
        Cert = 'false'
        Cli = ''
        SSM = ''
    }
    
    $password = (ConvertTo-SecureString -AsPlainText -Force 'ENTER-PASSWORD-HERE')
    
      $localUser = (Get-LocalUser -Name 'localuser' -ErrorAction SilentlyContinue)
        if(!$localUser) { 
          Write-host "$($args[0]) - Adding Local User"
          New-LocalUser -AccountNeverExpires:$true -Password $password -Name 'localuser' `
        | Add-LocalGroupMember -Group 'Administrators'
          $Results.LocalUser = 'Added'
        } else { 
          $Results.LocalUser = 'true'
          Write-host "$($args[0]) - Local User Already Exists" -ForegroundColor DarkYellow 
        }
      
      $AWSCERT = (Get-ChildItem Cert:\LocalMachine\AuthRoot\* | Where {$_.Subject -match "Amazon Root CA"}) -ne $null
        if($AWSCERT -eq $false) {
          Write-host "$($args[0]) - Installing AWS Certificate"
          Import-Certificate -FilePath "C:/temp/AmazonRootCA1.cer" -CertStoreLocation Cert:\LocalMachine\AuthRoot
          $Results.Cert = 'Added'
        } else { 
          $Results.Cert = 'true'
          Write-host "$($args[0]) - Certificate Already Exists" -ForegroundColor DarkYellow 
        }
      
      $AWSCLI = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.Displayname -match "AWS Command Line Interface v2"}) -ne $null
        if($AWSCLI -eq $false) {
          $Results.Cli = 'false'
          Write-host "$($args[0]) - Installing AWS CLI"
          Start-Process -Wait -FilePath msiexec -ArgumentList /i, "https://awscli.amazonaws.com/AWSCLIV2.msi", /qn
        } else {
          $Results.Cli = 'true'
          Write-host "$($args[0]) - AWS CLI Already Exists" -ForegroundColor DarkYellow 
        }
        
      $AWSSSM = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.Displayname -match "AWS SSM"}) -ne $null
        if($AWSSSM -eq $false) {
          $Results.SSM = 'true'
          Write-host "$($args[0]) - Installing SSM Agent"
          
            $progressPreference = 'silentlyContinue'
            Invoke-WebRequest `
                https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe `
                -OutFile $env:USERPROFILE\Desktop\SSMAgent_latest.exe
            
            Start-Process `
                -FilePath $env:USERPROFILE\Desktop\SSMAgent_latest.exe `
                -ArgumentList "/S"
            
            rm -Force $env:USERPROFILE\Desktop\SSMAgent_latest.exe
            
        } else {
          $Results.SSM = 'true'
          Write-host "$($args[0]) - AWS SSM AGENT Already Exists" -ForegroundColor DarkYellow 
        }
        
       Write-host "$($args[0]) - Starting Replication Installer" 
       $progressPreference = 'silentlyContinue'
       Invoke-WebRequest `
       https://aws-application-migration-service-<region>.s3.<region>.amazonaws.com/latest/windows/AwsReplicationWindowsInstaller.exe `
       -OutFile AWSReplicationWindowsInstaller.exe
            
       Start-Process -Credential $Using:credentials -PassThru -FilePath "C:\Temp\AwsReplicationWindowsInstaller.exe" -ArgumentList "--region us-east-1 --aws-access-key-id PUBLIC-KEY-HERE --aws-secret-access-key SECRET-KEY-HERE --no-prompt"
       
       Clear-Variable -Name AWS*
       Clear-variable -name localuser*
   
    return $Results
    } -ArgumentList $server 
    
    $Row.CERT = $serverResult.Cert
    $Row.LocalUser = $serverResult.LocalUser
    $Row.Cli = $serverResult.Cli
    $Row.SSM = $serverResult.SSM
    $Array += $Row
}

$array | Export-CSV  C:\Temp\PreMigration$(get-date -f 'HHMMss').csv -NoTypeInformation

```

