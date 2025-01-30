[string]$configFolderPath = "C:\DomainConfig\"
[string]$userFilePath = $configFolderPath + "users.json" # JSON File containing Users, Groups to assign to them, and other attributes for User creation.
[string]$domainStructureFilePath = $configFolderPath + "structure.json"  # JSON File containing OUs and attributes
[string]$logFilePath = $configFolderPath + "Get-Date -Format YYMMDDhh"


Class User{


}


function Write-ErrorLog($m, $e){
   
}

Switch (Test-Path $configFolderPath){
    $false {throw "Config Path could not be found!"}
    $true {return}
}

# Reads and Imports the Config Files used for Domain creation
function readConfigs(){
    $Script:userTemplates = Get-Content $userFilePath | ConvertFrom-Json -AsHashtable
}

# Creates Custom OUs and similar within the Domain
function createDomainStructure(){

}

# Handles Importing Users and Registering them in ADS
function registerUsers(){
    Get-Content $userFilePath | ConvertFrom-Json -AsHashtable

}