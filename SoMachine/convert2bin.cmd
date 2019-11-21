@echo off
SET somachine_path="C:\Program Files (x86)\Schneider Electric\SoMachine Software\V4.1\LogicBuilder.exe"
SET script_path=%1
SET project=%2
SET output=%3
%somachine_path% --noui^
 --runscript=%script_path%^
 --scriptargs:'%project% %output%'