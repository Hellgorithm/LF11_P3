@echo off

:: Map network drives for different groups

:: UserShares
net use Z: "D:\Freigaben\UserShares\%USERNAME%" /persistent:yes

:: Vorlagen
net use V: "D:\Freigaben\Vorlagen" /persistent:yes

:: Vorlagen_Ausk
net use W: "D:\Freigaben\Vorlagen_Ausk" /persistent:yes

:: Vorlagen_STB
net use X: "D:\Freigaben\Vorlagen_STB" /persistent:yes

:: Vorlagen_Beratung
net use Y: "D:\Freigaben\Vorlagen_Beratung" /persistent:yes

:: Vorlagen_Technik
net use T: "D:\Freigaben\Vorlagen_Technik" /persistent:yes

:: Vorlagen_GL
net use U: "D:\Freigaben\Vorlagen_GL" /persistent:yes

:: Transfer
net use R: "D:\Freigaben\Transfer" /persistent:yes

:: Transfer_Ausk
net use S: "D:\Freigaben\Transfer_Ausk" /persistent:yes

:: Transfer_STB
net use Q: "D:\Freigaben\Transfer_STB" /persistent:yes

:: Transfer_Beratung
net use P: "D:\Freigaben\Transfer_Beratung" /persistent:yes
echo Transfer Laufwerk für die Verbraucherberatung mapped to P:

:: Transfer_Technik
net use O: "D:\Freigaben\Transfer_Technik" /persistent:yes

:: Transfer_GL
net use N: "D:\Freigaben\Transfer_GL" /persistent:yes

pause