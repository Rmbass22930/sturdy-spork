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
FinishMessage=Codex53 New Projects setup complete.
TargetName=installer\Codex53NewProjectsSetup.exe
FriendlyName=Codex53 New Projects Setup
AppLaunched=Install.cmd
PostInstallCmd=<None>
AdminQuietInstCmd=Install.cmd
UserQuietInstCmd=Install.cmd
FILE0=Install.cmd
FILE1=run-setup.cmd
FILE2=setup-new-project-codex53.ps1
FILE3=setup-codex-chatgpt53.ps1
FILE4=run-install-powershell.cmd
FILE5=install-latest-powershell.ps1
FILE6=logincodex.ps1
FILE7=Start_Codex53.ps1
FILE8=codex_profile.ps1
FILE9=README.txt
FILE10=codex53-new-projects.pdf
FILE11=run-install-python.cmd
FILE12=install-latest-python.ps1

[SourceFiles]
SourceFiles0=installer\payload_codex53_new_projects\

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
