@echo off
SET somachine_path="C:\Program Files (x86)\Schneider Electric\SoMachine Software\V4.1\LogicBuilder.exe"
SET script_path=%1
SET project_template=%2
SET st_file=%3
SET output=%4
%somachine_path% --noui^
 --runscript=%script_path%^
 --scriptargs:'%project_template% %st_file% %output%'