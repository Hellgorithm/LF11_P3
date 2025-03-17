<#
.SYNOPSIS
    Domain configuration script for automated setup of a Microsoft ADDS environment.

.DESCRIPTION
    This script automates the configuration of an Active Directory domain environment including:
    - Creating organizational units (OUs)
    - Adding users from configuration files
    - Setting up network shares with proper permissions
    - Configuring DHCP settings
    - Configuring Print settings

    Please note that the last OS version this script was tested on is Windows Server 2022, support for future versions is not guaranteed.
    Script is unlikely to run on versions of Windows Server older than 2016.
    Last tested build: 20348.3328.

.PARAMETER None
    This script doesn't accept parameters directly but uses configuration files.
    By Default the script looks for "domainConfig.json" in the "configs" subfolder of the script directory.

.NOTES
    File Name      : DomainConfiguration.ps1
    Author         : Aaron Kain
    Prerequisite   : PowerShell 5.1 or later
                     Active Directory module
                     Administrative privileges
    Version        : 1.0
    Creation Date  : 10.01.2025
    Last Modified  : See Git Repository for latest changes

.EXAMPLE
    .\DomainConfiguration.ps1
    Runs the script using the configuration file specified in the script.

    Example Configuration Files can be found in the "configs" subfolder of the script directory.

.LINK
    https://github.com/Hellgorithm/LF11_P3
#>



#region Global Variables
[string]$configFolderPath = $PSScriptRoot + "\configs\" # Folder containing the Config Files for the Domain Configuration
[string]$configFilePath = $configFolderPath + "domainConfig.json" # JSON File containing Users, Groups to assign to them, and other attributes for User creation.
[string]$logFilePath = $PSScriptRoot + "DomainConfig.log" # Log File for the Domain Configuration Script
[string]$localDomain = "Lab0304.local" # Domain Name of the Local Environment
[string]$internetDomain = "biz-rundstadt.de" # Internet Routable/Searchable Domain Name
[string]$serverUNC = "\\$env:COMPUTERNAME" # UNC Path to the Server
$allUsers = New-Object -TypeName System.Collections.Generic.List[System.Object] # List containing all Users to be created, is filled once the Config File is read
$allShares = New-Object -TypeName System.Collections.Generic.List[System.Object] # List containing all Network Shares to be created, is filled once the Config File is read.

#endregion Global Variables

#region Classes
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
    User([hashtable]$params){
        $this.name = $params.Name
        $this.surname = $params.Surname
        $this.loginName = $params.LoginName
        $this.mailAddress = $params.MailAddress
        $this.groups = $params.Groups
        $this.homeShare = $params.HomeShare
        $this.ouPath = $params.OUPath
    }
    # [void] DisplayInfo() {
    #     Write-Host "Name: $($this.Name), Surname: $($this.Surname)"
    # }
}

class networkShare {
    [string]$name
    [string]$path
    [hashtable]$ntfsPermissions = @{}
    [hashtable]$sharePermissions = @{}

    networkShare($name, $path, $ntfsPermissions, $sharePermissions){
        $this.name = $name
        $this.path = $path
        $this.ntfsPermissions = $ntfsPermissions
        $this.sharePermissions = $sharePermissions
    }
}

#endregion Classes

#region Helper Functions
function Prune-Log(){
    $logContent = Get-Content -Path $logFilePath
    $logContent | Select-Object -Last $logContent.Length | Set-Content -Path $logFilePath
}

function Write-LogMessage($m, $e){
    try {
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
    catch {
        Write-EventLog -LogName Application -Source "DomainConfiguration" -EntryType Error -EventId 1 -Message "Error writing to Log File: $logFilePath, Error: $_"
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
    if (!(Test-Path $configFilePath)){
        Write-Output("Config File couldn't be found.")
        Write-LogMessage("Config File couldn't be found.", "Config File not found in directory $configFolderPath")
        exit
    }
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
        $allUsers.Add([User]::new($user.Name, $user.Surname, $user.loginName, $user.Groups, $serverUNC))
    }
    foreach ($share in $shareConfig){
        $allShares.Add([networkShare]::new($share.Name, $share.Path, $share.ntfsPermissions, $share.SharePermissions))
    }
}

# Creates Custom OUs and similar within the Domain
function createDomainStructure(){
    foreach ($ou in $ouConfig){
        Write-LogMessage("Creating OU $($ou.name)", $null)
        
        if (Get-ADOrganizationalUnit -Filter "distinguishedName -eq 'Mitarbeiter'") {
            try {
                New-ADOrganizationalUnit -Name $ou.name -Path $ou.DistinguishedName
            }
            catch {
                Write-LogMessage("Error creating OU $($ou.name)", $_)
            }
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

    foreach($share in $allShares){

        # Traverse the share Folder path, creating the necessary folders
        try {
            $private:index = 0
            $private:rejoinedPathList = New-Object -TypeName System.Collections.Generic.List[string]
            $private:folderPathParts = $share.Path -split "\\"
            foreach ($subFolder in $private:parentFolders){
                $private:rejoinedPathList = $private:folderPathParts[$private:index] + "\" + $subFolder
                $private:index++
                if (!(Test-Path $subFolder)){
                    New-Item -Path $subFolder -ItemType Directory
                }
            }
            $private:parentPath = Split-Path($share.path) -Parent
            New-Item -Path $share.path -ItemType Directory
        }
        catch {
            Write-LogMessage("Error creating Share $($share.name)", $_)

        }
        
        #Set NTFS Permissions
        $acl = Get-Acl -Path $share.path
        foreach ($key in $share.ntfsPermissions){
            $private:keyName = $($key.GetEnumerator() | Select-Object Key).Key

            $fileSystemACLArgumentList = @($private:keyName, $share.ntfsPermissions[$private:keyName], "ContainerInherit, ObjectInherit", "None", "Allow")
            $fileSystemACLR = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemACLArgumentList
            $acl.AddAccessRule($fileSystemACLR)
        }
        Set-Acl -Path $share.path -AclObject $acl
        New-SmbShare -Name $share.name -Path $share.path

        #Set Share Permissions
        foreach ($key in $share.sharePermissions){
            switch ($key) {
                "FullAccess" { Grant-SmbShareAccess -Name $share.name -AccountName $share.sharePermissions[$key] -AccessRight Full }
                "Write" { Grant-SmbShareAccess -Name $share.name -AccountName $share.sharePermissions[$key] -AccessRight Write }
                "Read" { Grant-SmbShareAccess -Name $share.name -AccountName $share.sharePermissions[$key] -AccessRight Read }
                Default {}
            }
        }
    }
}
#endregion Helper Functions

#region Main


#endregion Main