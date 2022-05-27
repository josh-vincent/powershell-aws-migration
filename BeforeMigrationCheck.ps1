$servers = Get-Content C:\temp\migrateServerList.csv
$credentials = Get-Credential # domain\username
$localPassword = 'local-password-here'

$Array = @() # Results stored here
foreach($server in $servers) {
    $Row = "" | Select-Object Server, LocalUser, LocalLogin, CERT, Cli, SSM, Replication
    $Row.Server = $server

    #Validate Local Login
    Clear-Variable -Name localLogin*
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $server)
    $localLogin = $DS.ValidateCredentials('localuser', $localPassword, [DirectoryServices.AccountManagement.ContextOptions]::Negotiate)


    Write-Host "$($server) ================================="
    $serverResult = Invoke-Command -ComputerName $server -Credential $credentials -ScriptBlock {

        $Results = New-Object PSObject -Property @{
            LocalUser = 'false'
            Cert = 'false'
            Cli = ''
            SSM = ''
            Replication = ''
        }

        #Import modules server might need
        Import-Module Microsoft.PowerShell.Utility

        $localUser = (Get-LocalUser -Name 'localuser' -ErrorAction SilentlyContinue)

        if(!$localUser) {
            $Results.LocalUser = 'FALSE'
        } else {
            $Results.LocalUser = 'TRUE'
        }

        $AWSCERT = (Get-ChildItem Cert:\LocalMachine\AuthRoot\* | Where {$_.Subject -match "Amazon Root CA"}) -ne $null

        if($AWSCERT -eq $false) {
            $Results.Cert = 'FALSE'
        } else {
            $Results.Cert = 'TRUE'
        }

        #Check CLI Exists
        if([System.IO.File]::Exists("C:\Program Files\Amazon\AWSCLIV2\aws.exe")){ $Results.Cli = 'TRUE' } else { $Results.Cli = 'FALSE' }

        #Check SSM Exists
        if([System.IO.File]::Exists("C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe")){ $Results.SSM = 'TRUE' } else { $Results.SSM = 'FALSE' }

        #Check Replication Agent Exists
        if([System.IO.File]::Exists("C:\Program Files (x86)\AWS Replication Agent\aws-replication-agent.jar")){ $Results.Replication = 'TRUE' } else { $Results.Replication = 'FALSE' }


        Clear-Variable -Name AWS*
        Clear-variable -name localuser*

        return $Results

    } -ArgumentList $server

    $Row.CERT = $serverResult.Cert
    $Row.LocalUser = $serverResult.LocalUser
    $Row.LocalLogin = $localLogin
    $Row.Cli = $serverResult.Cli
    $Row.SSM = $serverResult.SSM
    $Row.Replication = $serverResult.Replication
    $Array += $Row
}

$array | Export-CSV  "C:\Temp\PreMigrationCheck$(Get-Date -Format "HHmm").csv" -NoTypeInformation

$array