[string]$configFolderPath = $PSScriptroot + "\configs\" # Folder containing the Config Files for the Domain Configuration
[string]$userFilePath = $configFolderPath + "users.json" # JSON File containing Users, Groups to assign to them, and other attributes for User creation.
[string]$domainStructureFilePath = $configFolderPath + "structure.json"  # JSON File containing OUs and attributes
[string]$logFilePath = $configFolderPath + "DomainConfig.log" # Log File for the Domain Configuration Script


class User {
    [string]$name
    [string]$surname
    [string]$loginName
    [string[]]$groups
    [string]$homeShare

    User($name, $surname, $loginName, $groups) {
        $this.name = $name
        $this.surname = $surname
        $this.loginName = $loginName
        $this.groups = $groups
    }

    # [void] DisplayInfo() {
    #     Write-Host "Name: $($this.Name), Surname: $($this.Surname)"
    # }
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

function Prune-Log(){
    $logContent = Get-Content -Path $logFilePath
    $logContent | Select-Object -Last 100 | Set-Content -Path $logFilePath
}

Switch (Test-Path $configFolderPath){
    $false {throw "Config Path could not be found!"}
    $true {return}
}

# Reads and Imports the Config Files used for Domain creation
function readConfigs(){
    $DataBlob
}


# Creates Custom OUs and similar within the Domain
function createDomainStructure(){

}

# Handles Importing Users and Registering them in ADS
function registerUsers(){
    Get-Content $userFilePath | ConvertFrom-Json -AsHashtable

}