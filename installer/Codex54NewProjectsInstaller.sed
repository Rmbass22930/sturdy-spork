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
InstallPrompt=
DisplayLicense=
FinishMessage=Codex54 New Projects setup complete.
TargetName=installer\Codex54NewProjectsSetup.exe
FriendlyName=Codex54 New Projects Setup
AppLaunched=Install.cmd
PostInstallCmd=<None>
AdminQuietInstCmd=Install.cmd
UserQuietInstCmd=Install.cmd
FILE0=Install.cmd
FILE1=run-setup.cmd
FILE2=setup-new-project-codex54.ps1
FILE3=setup-codex-chatgpt54.ps1
FILE4=run-install-powershell.cmd
FILE5=install-latest-powershell.ps1
FILE6=logincodex.ps1
FILE7=Start_Codex54.ps1
FILE8=Start_Codex54.cmd
FILE9=codex_profile.ps1
FILE10=README.txt
FILE11=codex54 new projects.pdf
FILE12=run-install-python.cmd
FILE13=install-latest-python.ps1
FILE14=Start_Codex53.ps1
FILE15=Start_Codex5.ps1

[SourceFiles]
SourceFiles0=installer\payload_codex54_new_projects\

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
%FILE9%=
%FILE10%=
%FILE11%=
%FILE12%=
%FILE13%=
%FILE14%=
%FILE15%=
