Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"} | ForEach-Object {Disable-WindowsOptionalFeature -FeatureName $_.FeatureName -Online -NoRestart -Confirm:$false}
