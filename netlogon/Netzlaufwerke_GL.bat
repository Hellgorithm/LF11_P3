@echo off

:: Map network drives for different groups

:: UserShares
net use Z: "\\gr3-dc\UserShares\%USERNAME%" /persistent:yes

:: Vorlagen
net use V: "\\gr3-dc\Vorlagen" /persistent:yes

:: Vorlagen_Ausk
net use W: "\\gr3-dc\Vorlagen_Ausk" /persistent:yes

:: Vorlagen_STB
net use X: "\\gr3-dc\Vorlagen_STB" /persistent:yes

:: Vorlagen_Beratung
net use Y: "\\gr3-dc\Vorlagen_Beratung" /persistent:yes

:: Vorlagen_Technik
net use T: "\\gr3-dc\Vorlagen_Technik" /persistent:yes

:: Vorlagen_GL
net use U: "\\gr3-dc\Vorlagen_GL" /persistent:yes

:: Transfer
net use R: "\\gr3-dc\Transfer" /persistent:yes

:: Transfer_Ausk
net use S: "\\gr3-dc\Transfer_Ausk" /persistent:yes

:: Transfer_STB
net use Q: "\\gr3-dc\Transfer_STB" /persistent:yes

:: Transfer_Beratung
net use P: "\\gr3-dc\Transfer_Beratung" /persistent:yes
echo Transfer Laufwerk für die Verbraucherberatung mapped to P:

:: Transfer_Technik
net use O: "\\gr3-dc\Transfer_Technik" /persistent:yes

:: Transfer_GL
net use N: "\\gr3-dc\Transfer_GL" /persistent:yes
