@echo off

:: Laufwerke Allgemein
net use V: "\\gr3-dc\Vorlagen" /persistent:yes
net use R: "\\gr3-dc\Transfer" /persistent:yes

:: Laufwerke Auskunft
net use S: "\\gr3-dc\Transfer_Ausk" /persistent:yes
net use W: "\\gr3-dc\Vorlagen_Ausk" /persistent:yes