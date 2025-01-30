[string]$configFolderPath = $PSScriptRoot + "\configs\" # Folder containing the Config Files for the Domain Configuration
[string]$configFilePath = $configFolderPath + "domainConfig.json" # JSON File containing Users, Groups to assign to them, and other attributes for User creation.
[string]$logFilePath = $PSScriptRoot + "DomainConfig.log" # Log File for the Domain Configuration Script
[string]$serverUNC = "\\$env:COMPUTERNAME" # UNC Path to the Server
$allUsers = @() # Array containing all Users to be created, is filled once the Config File is read


class User {
    [string]$name
    [string]$surname
    [string]$loginName
    [string[]]$groups
    [string]$homeShare

    User($name, $surname, $loginName, $groups, $serverUNC) {
        $this.name = $name
        $this.surname = $surname
        $this.loginName = $loginName
        $this.groups = $groups
        $this.homeShare = $serverUNC + $loginName + "$"
    }

    # [void] DisplayInfo() {
    #     Write-Host "Name: $($this.Name), Surname: $($this.Surname)"
    # }
}




function Prune-Log(){
    $logContent = Get-Content -Path $logFilePath
    $logContent | Select-Object -Last 100 | Set-Content -Path $logFilePath
}

function Write-LogMessage($m, $e){
    $logMessage = "$(Get-Date -Format "dd.MM.yyyy HH:mm:ss")`n    - $m"
    if ($e -ne $null){
        $logMessage += "`n    - Exception: $e"
    }
    Add-Content -Path $logFilePath -Value $logMessage
    # Write-Host $logMessage
    if ((Get-Item $logFilePath).Length -gt 2MB) {
        Prune-Log
    }
}

Switch (Test-Path $configFolderPath){
    $false {throw "Config Path could not be found!"}
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
        $allUsers += User::new($user.Name, $user.Surname, $user.LoginName, $user.Groups, $serverUNC)
    }
}


# Creates Custom OUs and similar within the Domain
function createDomainStructure(){

}

# Handles Importing Users and Registering them in ADS
function registerUsers(){
    

}