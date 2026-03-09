[Version]
Class=IEXPRESS
SEDVersion=3

[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=1
HideExtractAnimation=1
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=%InstallPrompt%
DisplayLicense=%DisplayLicense%
FinishMessage=%FinishMessage%
TargetName=%TargetName%
FriendlyName=%FriendlyName%
AppLaunched=%AppLaunched%
PostInstallCmd=%PostInstallCmd%
AdminQuietInstCmd=%AdminQuietInstCmd%
UserQuietInstCmd=%UserQuietInstCmd%
SourceFiles=SourceFiles

[Strings]
InstallPrompt=This will extract and install Ballistic Target Calculator to your Desktop. Click OK to continue.
DisplayLicense=
FinishMessage=Ballistic Target Calculator installation complete. Check your Desktop folder for "ballilstic target calulator".
TargetName=InstallBallistic.exe
FriendlyName=Ballistic Target Calculator Setup
AppLaunched=Install.cmd
PostInstallCmd=<None>
AdminQuietInstCmd=Install.cmd
UserQuietInstCmd=Install.cmd
FILE0=Install.cmd
FILE1=BallisticTargetGUI.exe
FILE2=EnvironmentalsGeoGUI.exe
FILE3=Uninstall.exe
FILE4=README.txt
FILE5=config.template.json
FILE6=EnvironmentalsGeo_iOS.html
FILE7=BallisticTarget_iOS.html
FILE8=TargetUsage.txt

[SourceFiles]
SourceFiles0=payload\

[SourceFiles0]
%FILE0%=
%FILE1%=
%FILE2%=
%FILE3%=
%FILE4%=
%FILE5%=
%FILE6%=
%FILE7%=
%FILE8%=

