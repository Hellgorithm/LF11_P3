$Druckserver = "\\GR3-DC"

$Benutzer = "gr3.laba304.local\TestD"

$Rechte = "Deny"


Write-Host "Setze berechtigung '$Rechte' für $Benutzer auf Druckserver $Druckserver" -ForegroundColor Green
Set-Printer -ComputerName $Druckserver -Permission "$Benutzer, $Rechte, Allow"