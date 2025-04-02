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
    Author         : HGR
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

#requires -RunAsAdministrator 
#requires -Version 5.1
#requires -Modules ActiveDirectory, PrintManagement


#region Global Variables
[string]$configFolderPath = $PSScriptRoot + "\configs\" # Folder containing the Config Files for the Domain Configuration
[string]$configFilePath = $configFolderPath + "domainConfig.json" # JSON File containing Users, Groups to assign to them, and other attributes for User creation.
[string]$logFilePath = $PSScriptRoot + "DomainConfig.log" # Log File for the Domain Configuration Script
[string]$localDomain = "laba304.local" # Domain Name of the Local Environment
[string]$internetDomain = "biz-rundstadt.de" # Internet Routable/Searchable Domain Name
[string]$serverUNC = "\\$env:COMPUTERNAME" # UNC Path to the Server
[int]$maxLogSize = 2MB # Maximum Size of the Log File before it is pruned
[string]$groupPrefix = "grp_" # Prefix for all Groups created by the script
[string]$noPrintGroup = $groupPrefix + "Besucher" # Group that is denied print access to all printers. If null, no group is denied print access. DONT REMOVE THE PREFIX UNLESS NULL!
[System.Collections.Generic.List[string]]$noneOuGroups = @(
    "Domain Admins",
    "Domänen-Admins",
    "Domänen-Benutzer",
    "Besucher",
    "Alle-MA"
) # Groups that will be ignored when attempting to Auto-Assign OUs to Users during the reading of config files
#$noneOuGroups = $noneOuGroups | ForEach-Object { $groupPrefix + $_ } # Add the Group Prefix to the Group Names
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
    [string]$UPN

    User($name, $surname, $loginName, $groups, $serverUNC, $ouPath, $internetDomain){
        $this.name = $name
        $this.surname = $surname
        $this.loginName = $loginName
        $this.mailAddress = $name + "." + $surname + "@" + $internetDomain
        $this.groups = $groups
        $this.homeShare = $serverUNC + "\" +  $loginName + "$"
        $this.ouPath = $ouPath
        $this.UPN = $loginName + "@" + $script:localDomain


    }
    User([hashtable]$params){
        $this.name = $params.Name
        $this.surname = $params.Surname
        $this.loginName = $params.LoginName
        $this.mailAddress = $params.MailAddress
        $this.groups = $params.Groups
        $this.homeShare = $params.HomeShare
        $this.ouPath = $params.OUPath
        $this.UPN = $params.Name + "@" + $script:localDomain
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
        $this.ntfsPermissions = @{}
        $this.sharePermissions = @{}
        foreach ($perm in $ntfsPermissions){
            $this.ntfsPermissions.Add($perm.Name, $perm.Permission)
        }
        foreach ($perm in $sharePermissions){
            $this.sharePermissions.Add($perm.Name, $perm.Permission)
        }
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
        if ($null -ne $e){
            $logMessage += "`r`n    - Exception: $e`r`n"
        }
        Add-Content -Path $logFilePath -Value $logMessage
        if ((Get-Item $logFilePath).Length -gt $maxLogSize){ {
            Prune-Log
        }
        }
    }
    catch {
        Write-EventLog -LogName Application -Source "DomainConfiguration" -EntryType Error -EventId 1 -Message "Error writing to Log File: $logFilePath, Error: $_"
    }
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
    # Import Users, assign them to OUs automatically if possible. If not, prompt User.
    foreach ($user in $userConfig){
        if (Get-Variable -Name cleanedGroups -ErrorAction SilentlyContinue){
            Remove-Variable -Name cleanedGroups
        }
        
        $private:cleanedGroups = New-Object -TypeName System.Collections.Generic.List[string]
        foreach ($grp in $user.GroupMemberships){
            if ($noneOuGroups -notcontains $grp){
                $cleanedGroups.Add($grp)
            }
        } # Array to store the group names without Groups that cant be assigned an OU automatically

        if (($cleanedGroups.Count -gt 0) -and ($cleanedGroups.Count -le 1)){
            $private:userOuPath = $ouConfig | Where-Object {$_.Name -like "*$($user.GroupMemberships[0])"}
            $userOuPath = "OU=" + $userOuPath.Name + "," + $userOuPath.DistinguishedName
        }
        else {
            $private:ouChoice = Read-Host("Multiple Groups detected. Enter the OU Name for User $($user.Name) $($user.Surname)`r`nGroup Memberships: $($user.GroupMemberships)`r`nDISCLAIMER: Only OUs defined in the Config File will be accepted.")
            $private:userOuPath = $ouConfig | Where-Object {$_.Name -eq ("MA-" + $ouChoice)}
            $userOuPath = "OU=" + $userOuPath.Name + "," + $userOuPath.DistinguishedName
        }
        $allUsers.Add([User]::new($user.Name, $user.Surname, $user.loginName, $user.GroupMemberships, $serverUNC, $private:userOuPath, $internetDomain))
    }
    foreach ($share in $shareConfig){
        $allShares.Add([networkShare]::new($share.Name, $share.Path, $share.ntfsPermissions, $share.SharePermissions))
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

function registerGroups(){
    foreach ($group in $groupConfig){
        Write-LogMessage("Creating Group $($group.name)", $null)
        try {
            New-ADGroup -Name ($groupPrefix + $group.name) -Path $group.ouPath -GroupScope DomainLocal -GroupCategory Security
            Write-Host("Group $($group.name) created successfully.") -ForegroundColor Green
        }
        catch {
            Write-LogMessage("Error creating Group $($group.name)", $_)
            Write-Host("Error creating Group $($group.name).") -ForegroundColor Red
        }
    }   
}

# Handles Importing Users and Registering them in ADS
function registerUsers(){
    $Private:startPW = Read-Host -Prompt "Enter the starting Password for the new Users." -AsSecureString
    foreach ($user in $allUsers){
        Write-LogMessage("Creating User $($user.loginName)", $null)
        try {

            # Create HomeShare on the Server
            $private:homeSharePath = $user.loginName + "$"
            $private:homeSharePath = $serverUNC + "\" + "Freigaben" + "\" + "UserShares" + "\" + $private:homeSharePath
            
            if (!(Test-Path $private:homeSharePath)){
                New-Item -Path $private:homeSharePath -ItemType Directory
                Write-Host("Home Share $($user.loginName) created successfully.") -ForegroundColor Green
            }
            else {
                Write-Host("Home Share $($user.loginName) already exists.") -ForegroundColor Yellow
            }
            

            New-ADUser -GivenName $user.name -Surname $user.surname -Name ($user.surname + ", " + $user.name) -DisplayName ($user.surname + ", " + $user.name) -UserPrincipalName $user.UPN -SamAccountName $user.loginName -AccountPassword $startPW -Enabled $true -Path $user.ouPath -EmailAddress $user.mailAddress -HomeDrive "H:" -HomeDirectory $user.homeShare -ChangePasswordAtLogon $true
            Write-Host("User $($user.loginName) created successfully.") -ForegroundColor Green
            Write-Host("User Groups: $($user.groups)") -ForegroundColor Cyan
            foreach ($group in $user.groups){
                try {
                    if ($group -ne "Domain Admins"){
                        Write-Host("Hit Group adding loop") -ForegroundColor Cyan
                        Add-ADGroupMember -Identity ($groupPrefix +  $group) -Members $user.loginName
                        Write-Host("User $($user.loginName) added to Group $($groupPrefix + $group).") -ForegroundColor Green
                    }
                    else {
                        Add-ADGroupMember -Identity "Domänen-Admins" -Members $user.loginName
                        Write-Host("User $($user.loginName) added to Group Domain Admins.") -ForegroundColor Green
                    }
                } 
                catch {
                    Write-LogMessage("Error adding User $($user.loginName) to Group $($group)", $_)
                    Write-Host("Error adding User $($user.loginName) to Group $($group).") -ForegroundColor Red
                }
            }
            # Set NTFS Permissions for the HomeShare
            $private:homeShareACL = Get-Acl -Path $private:homeSharePath
            $private:homeShareACL.SetAccessRuleProtection($true, $false) # Preserve existing permissions and disable inheritance
            $private:homeShareACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($user.loginName,"FullControl","ContainerInherit, ObjectInherit","None","Allow")))
            $private:homeShareACL | Set-Acl -Path $private:homeSharePath

            # Set Share Permissions for the HomeShare
            $private:homeShareShare = Get-SmbShare -Name $private:homeSharePath
            $private:everyonePermExists = $private:homeShareShare | Get-SmbShareAccess | Where-Object { $_.AccountName -match "Jeder" } 

            Grant-SmbShareAccess -Name $private:homeSharePath -AccountName $user.loginName -AccessRight Full -Force
            if ($everyonePermExists){
                Revoke-SmbShareAccess -Name $private:homeSharePath -AccountName "Jeder" -Force
            }
            # Add-ADGroupMember -Identity "Domänen-Benutzer" -Members $user.loginName
            # Write-Host("User $($user.loginName) added to Group Domain Users.") -ForegroundColor Green
        }
        catch {
            Write-LogMessage("Error creating User $($user.loginName)", $_)
            Write-Host("Error creating User $($user.loginName).") -ForegroundColor Red
        }
    }
    Remove-Variable -Name startPW
    Write-Host("All Users created successfully.") -ForegroundColor Green
}

function createNetworkShares(){
    foreach($share in $allShares){
        $private:index = 0
        # Traverse the share Folder path, creating the necessary folders
        try {
            if (Get-Variable -Name rejoinedPathList -ErrorAction SilentlyContinue){
                Remove-Variable -Name rejoinedPathList
            }

            $private:rejoinedPathList = New-Object -TypeName System.Collections.Generic.List[string]
            $private:folderPathParts = $share.Path -split "\\"

            foreach ($subFolder in $folderPathParts){
                if ($index -eq 0){
                    $rejoinedPathList.Add($subFolder + "\\")
                }
                else {
                    $rejoinedPathList.Add($folderPathParts[$index] + "\\")
                }
                $private:rejoinedPath = [string]::Concat($rejoinedPathList)
                if (!(Test-Path $rejoinedPath)){
                    New-Item -Path $rejoinedPath -ItemType Directory
                }
                $index++
            }
            Write-Host("Share Folder $($share.name) created successfully.") -ForegroundColor Green
        }
        catch {
            Write-LogMessage("Error creating Share $($share.name)", $_)
            Write-Host("Error creating Share $($share.name).") -ForegroundColor Red

        }
        
        #Set NTFS Permissions
        $acl = Get-Acl -Path $share.path
        foreach ($key in $share.ntfsPermissions.Keys){
            $private:groupName = $groupPrefix + $key
            switch ($share.ntfsPermissions[$key]) {
                "FullAccess" { $private:newACE = @{
                    IdentityReference = $groupName
                    FileSystemRights = "FullControl"
                    InheritanceFlags = "ContainerInherit, ObjectInherit"
                    PropogationFlags = "None"
                    AccessControlType = "Allow"
                    }
                }
                "Modify" { $private:newACE = @{
                    IdentityReference = $groupName 
                    FileSystemRights = "Modify"
                    InheritanceFlags = "ContainerInherit, ObjectInherit"
                    PropogationFlags = "None"
                    AccessControlType = "Allow"
                    }
                }
                "ReadAndExecute" { $private:newACE = @{
                    IdentityReference = $groupName
                    FileSystemRights = "ReadAndExecute"
                    InheritanceFlags = "ContainerInherit, ObjectInherit"
                    PropogationFlags = "None"
                    AccessControlType = "Allow"
                    } 
                }
                Default {Write-LogMessage("Error setting NTFS Permissions for $($share.name)", "Invalid NTFS Permission (Hit default case)")}
            }
            $private:fileSystemACLR = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($newACE.IdentityReference, $newACE.FileSystemRights, $newACE.InheritanceFlags, $newACE.PropogationFlags, $newACE.AccessControlType)
            $acl.SetAccessRuleProtection($true, $false) # Preserve existing permissions and disable inheritance
            $acl.AddAccessRule($fileSystemACLR)
        }
        $acl | Set-Acl

        New-SmbShare -Name $share.name -Path $share.path

        #Set Share Permissions
        foreach ($key in $share.sharePermissions.Keys){
            $private:groupName = $groupPrefix + $key
            switch ($share.sharePermissions[$key]) {
                "FullAccess" { Grant-SmbShareAccess -Name $share.name -AccountName $groupName -AccessRight Full }
                "Change" { Grant-SmbShareAccess -Name $share.name -AccountName $groupName -AccessRight Change }
                "Read" { Grant-SmbShareAccess -Name $share.name -AccountName $groupName -AccessRight Read }
                Default {Write-LogMessage("Error setting Share Permissions for $($share.name)", "Invalid Share Permission (Hit default case)")}
            }

            # Remove Everyone Share Access if it exists
            $private:everyonePermExists = Get-SmbShare -Name $share.name | Get-SmbShareAccess | Where-Object { $_.AccountName -match "Jeder" }
            if ($everyonePermExists){
                Revoke-SmbShareAccess -Name $share.name -AccountName "Jeder" -Force
            }
            Write-Host("Share Permissions for $($share.name) set successfully.") -ForegroundColor Green
        }
    }
}

function configurePrinters() {
    Write-LogMessage("Starting printer configuration", $null)
    
    # Check if printer configuration exists in the JSON
    if ($null -eq $Script:DataBlob.Printers) {
        Write-LogMessage("No printer configuration found in config file", $null)
        Write-Host("No printer configuration found in config file") -ForegroundColor Yellow
        return
    }
    
    foreach ($printer in $Script:DataBlob.Printers) {
        try {
            Write-LogMessage("Configuring printer $($printer.Name)", $null)
            # Add printer port if it doesn't exist
            if (!(Get-PrinterPort -Name $printer.PortName -ErrorAction SilentlyContinue)) {
                Add-PrinterPort -Name $printer.PortName -PrinterHostAddress $printer.PortName
            }
            
            # Add printer if it doesn't exist
            if (!(Get-Printer -Name $printer.Name -ErrorAction SilentlyContinue)) {
                Add-Printer -Name $printer.Name -DriverName $printer.DriverName -PortName $printer.PortName -Shared:$true -ShareName $printer.Name
            }
            
            # Configure print permissions
            # Remove all existing permissions first
            Set-PrinterPermission -PrinterName $printer.Name -RemoveAllPermissions
            
            # Add allow permissions
            foreach ($group in $printer.PrintPermissions.Allow) {
                Set-PrinterPermission -PrinterName $printer.Name -UserName $group -AccessRight Print
                Write-Host("Granted print permission to $group for printer $($printer.Name)") -ForegroundColor Green
            }
            
            # Add deny permissions
            foreach ($group in $printer.PrintPermissions.Deny) {
                Set-PrinterPermission -PrinterName $printer.Name -UserName $group -AccessRight NoAccess
                Write-Host("Denied print permission to $group for printer $($printer.Name)") -ForegroundColor Green
            }
            
            # Specifically deny print access to $noPrintGroup if it exists but isn't already in deny list
            if ((Get-ADGroup -Filter "Name -eq '$noPrintGroup'" -ErrorAction SilentlyContinue) -and 
                ($printer.PrintPermissions.Deny -notcontains "$noPrintGroup") -and ($null -ne $noPrintGroup)) {
                Set-PrinterPermission -PrinterName $printer.Name -UserName "$noPrintGroup" -AccessRight NoAccess
                Write-Host("Denied print permission to $noPrintGroup for printer $($printer.Name)") -ForegroundColor Green
            }
            
            Write-Host("Printer $($printer.Name) configured successfully") -ForegroundColor Green
        }
        catch {
            Write-LogMessage("Error configuring printer $($printer.Name)", $_)
            Write-Host("Error configuring printer $($printer.Name)") -ForegroundColor Red
        }
    }
}

function configureDHCP(){
    # Check if DHCP Feature is installed.
    if (!(Get-WindowsFeature -Name DHCP | Where Installed)){
        try {
            Install-WindowsFeature -Name DHCP -IncludeManagementTools
        }
        catch {
            Write-LogMessage("Error installing DHCP Feature", $_)
            Write-Host("DHCP Feature not installed`r`nError installing DHCP Feature") -ForegroundColor Red
        } 
    }

    # Check if DHCP server is authorized in Active Directory
    $existingDHCPServer = Get-DhcpServerInDC | Where-Object { $_.DnsName -eq "$env:COMPUTERNAME.$localDomain" }
    $existingDHCPScope = Get-DhcpServerv4Scope -ComputerName $env:COMPUTERNAME 
    if (!$existingDhcpServer) {
        Write-LogMessage("DHCP server not authorized, authorizing it now", $null)
        try {
            Add-DhcpServerInDC -DnsName "$env:COMPUTERNAME.$localDomain" -IpAddress $dhcpConfig.DnsServer
            Write-Host("DHCP server authorized successfully") -ForegroundColor Green
        }
        catch {
            Write-LogMessage("Error authorizing DHCP server", $_)
            Write-Host("Error authorizing DHCP server") -ForegroundColor Red
        }
    }
    else {
        Write-LogMessage("DHCP server already authorized, skipping authorization", $null)
        Write-Host("DHCP server already authorized") -ForegroundColor Green
    }

    #Check if DHCP Scope already exists, remove if so.
    if (!$existingDHCPScope) {
        Write-LogMessage("DHCP scope not found, creating it now", $null)
        try{
            Add-DhcpServerv4Scope -Name $dhcpConfig.Name -StartRange $dhcpConfig.ScopeStart -EndRange $dhcpConfig.ScopeEnd -SubnetMask $dhcpConfig.SubnetMask -LeaseDuration $dhcpConfig.LeaseDuration -State Active
            
            Set-DhcpServerV4OptionValue -ScopeId $dhcpConfig.ScopeID -DnsServer $dhcpConfig.DnsServer -Router $dhcpConfig.Gateway -DnsDomain $localDomain

            Write-Host("DHCP Scope and Options configured successfully") -ForegroundColor Green
            Write-LogMessage("DHCP Scope and Options configured successfully", $null)
        }
        catch{
            Write-LogMessage("Error creating DHCP scope", $_)
            Write-Host("Error creating DHCP scope") -ForegroundColor Red
        }
    }
    else {
        Write-Host "Found DHCP scope: $($existingDHCPScope.Name) with ID $($existingDHCPScope.ScopeId)" -ForegroundColor Yellow
        # Prompt for confirmation
        $confirmation = Read-Host "Are you sure you want to remove this scope? (y/n)"
        # Loop until a valid input is received
        while($confirmation.ToLower() -ne 'y' -and $confirmation.ToLower() -ne 'n'){
            Write-Host "Invalid input. Please enter 'y' to remove or 'n' to skip DHCP configuration." -ForegroundColor Red
            $confirmation = Read-Host "Are you sure you want to remove this scope? (y/n)"
        }

        if ($confirmation -eq 'y') {
            try {
                # Remove the scope
                Remove-DhcpServerv4Scope -ScopeId $scopeId -Force
                Write-Host "DHCP Scope has been removed successfully" -ForegroundColor Green
                Write-LogMessage "DHCP Scope has been removed successfully", $null
            }
            catch {
                Write-LogMessage("Error removing DHCP scope", $_)
                Write-Host "Error removing DHCP scope" -ForegroundColor Red
            }
            try {
                Add-DhcpServerv4Scope -Name $dhcpConfig.Name -StartRange $dhcpConfig.ScopeStart -EndRange $dhcpConfig.ScopeEnd -SubnetMask $dhcpConfig.SubnetMask -LeaseDuration $dhcpConfig.LeaseDuration -State Active
        
                Set-DhcpServerV4OptionValue -ScopeId $dhcpConfig.ScopeID -DnsServer $dhcpConfig.DnsServer -Router $dhcpConfig.Gateway -DnsDomain $localDomain

                Write-Host("DHCP Scope and Options configured successfully") -ForegroundColor Green
                Write-LogMessage("DHCP Scope and Options configured successfully", $null)
            }
            catch {
                Write-LogMessage("Error creating DHCP scope", $_)
                Write-Host("Error creating DHCP scope") -ForegroundColor Red
            }                
        }
        else {
            Write-Host "Scope removal cancelled" -ForegroundColor Cyan
            Write-Host "Skipping DHCP scope creation" -ForegroundColor Yellow
            return
        }
    }
}

#endregion Helper Functions

#region Main
function Main(){
    readConfigs("all")
    createDomainStructure
    registerGroups
    registerUsers
    createNetworkShares
    # configureDHCP
}

#endregion Main

Main