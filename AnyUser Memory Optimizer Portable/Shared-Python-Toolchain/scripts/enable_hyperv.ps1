Write-Host "Enabling Hyper-V features (requires restart)..."
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Tools-All -NoRestart
Write-Host "Hyper-V enabled. Please restart Windows to finish installation."
