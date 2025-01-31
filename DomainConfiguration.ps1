[string]$configFolderPath = $PSScriptRoot + "\configs\" # Folder containing the Config Files for the Domain Configuration
[string]$configFilePath = $configFolderPath + "domainConfig.json" # JSON File containing Users, Groups to assign to them, and other attributes for User creation.
[string]$logFilePath = $PSScriptRoot + "DomainConfig.log" # Log File for the Domain Configuration Script
[string]$localDomain = "Lab0304.local" # Domain Name of the Local Environment
[string]$internetDomain = "biz-rundstadt.de" # Internet Routable/Searchable Domain Name
[string]$serverUNC = "\\$env:COMPUTERNAME" # UNC Path to the Server
$allUsers = @() # Array containing all Users to be created, is filled once the Config File is read


class User {
    [string]$name
    [string]$surname
    [string]$loginName
    [string]$mailAddress
    [string[]]$groups
    [string]$homeShare
    [string]$ouPath

    User($name, $surname, $loginName, $groups, $serverUNC, $ouPath, $internetDomain){
        $this.name = $name
        $this.surname = $surname
        $this.loginName = $loginName
        $this.mailAddress = $name + "." + $surname + $internetDomain
        $this.groups = $groups
        $this.homeShare = $serverUNC + $loginName + "$"
        $this.ouPath = $ouPath
    }

    # [void] DisplayInfo() {
    #     Write-Host "Name: $($this.Name), Surname: $($this.Surname)"
    # }
}

class networkShare {
    [string]$name
    [string]$path
    [hashtable]$NTFSPermissions = @{}
    [hashtable]$sharePermissions = @{}

    networkShare($name, $path, $NTFSPermissions, $sharePermissions){
        $this.name = $name
        $this.path = $path
        $this.NTFSPermissions = $NTFSPermissions
        $this.sharePermissions = $sharePermissions
    }
}




function Prune-Log(){
    $logContent = Get-Content -Path $logFilePath
    $logContent | Select-Object -Last $logContent.Length | Set-Content -Path $logFilePath
}

function Write-LogMessage($m, $e){
    $logMessage = "$(Get-Date -Format "dd.MM.yyyy HH:mm:ss")`r`n    - Message: $m"
    if ($e -ne $null){
        $logMessage += "`r`n    - Exception: $e`r`n"
    }
    Add-Content -Path $logFilePath -Value $logMessage
    # Write-Host $logMessage
    if ((Get-Item $logFilePath).Length -gt 2MB) {
        Prune-Log
    }
}

Switch (Test-Path $configFolderPath){
    $false {Write-Output("Config Folder couldn't be found.")
            Write-LogMessage("Config Folder couldn't be found.", "Configs not found in directory $configFolderPath")
            exit}
    $true {return}
}

# Reads and Imports the Config Files used for Domain creation
function readConfigs($selConfig){
    $private:DataBlob = Get-Content $configFilePath | ConvertFrom-Json
    switch ($selConfig) {
        "user" { $userConfig = $DataBlob.Users }
        "group" { $groupConfig = $DataBlob.Groups }
        "ou" { $ouConfig = $DataBlob.OUs }
        "share" { $shareConfig = $DataBlob.Folders }
        "dhcp" { $dhcpConfig = $DataBlob.DHCP }
        Default { 
            $private:userConfig = $DataBlob.Users
            $Script:groupConfig = $DataBlob.Groups
            $Script:ouConfig = $DataBlob.OUs
            $Script:shareConfig = $DataBlob.Folders
            $Script:dhcpConfig = $DataBlob.DHCP
        }
    }
    foreach ($user in $userConfig){
        $allUsers += User::new($user.Name, $user.Surname, $user.loginName, $user.Groups, $serverUNC)
    }
}


# Creates Custom OUs and similar within the Domain
function createDomainStructure(){
    foreach ($ou in $ouConfig){
        Write-LogMessage("Creating OU $($ou.name)", $null)
        try {
            New-ADOrganizationalUnit -Name $ou.name -Path $ou.DistinguishedName
        }
        catch {
            Write-LogMessage("Error creating OU $($ou.name)", $_)
        }
    }
}

# Handles Importing Users and Registering them in ADS
function registerUsers(){
    $Private:startPW = ConvertTo-SecureString $(Read-Host -Prompt "Enter the starting Password for the new Users.") -AsPlainText -Force
    foreach ($user in $allUsers){
        Write-LogMessage("Creating User $($user.loginName)", $null)
        try {
            New-ADUser -Name $user.name -Surname $user.surname -SamAccountName $user.loginName -AccountPassword $startPW -Enabled $true -Path $user.ouPath -EmailAddress $user.mailAddress -HomeDrive "H:" -HomeDirectory $user.homeShare -ChangePasswordAtLogon $true
        }
        catch {
            Write-LogMessage("Error creating User $($user.loginName)", $_)
        }
    }
}

function createNetworkShares(){
    foreach ($share in $shareConfig){
        Write-LogMessage("Creating Share $($share.name)", $null)
        try {
            New-Item -Path $share.path -ItemType Directory
            $acl = Get-Acl -Path $share.path
            foreach ($key in $share.NTFSPermissions.Keys){
                $fileSystemACLArgumentList = @($key, $share.NTFSPermissions[$key], "ContainerInherit, ObjectInherit", "None", "Allow")
                $fileSystemACLR = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemACLArgumentList
                $acl.AddAccessRule($fileSystemACLR)
            }
            Set-Acl -Path $share.path -AclObject $acl
            New-SmbShare -Name $share.name -Path $share.path -FullAccess "Everyone"
        }
        catch {
            Write-LogMessage("Error creating Share $($share.name)", $_)
        }
    }
}