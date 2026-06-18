#requires -Version 5.1
<#
.SYNOPSIS
    SMB NTFS Reporter.
.DESCRIPTION
    Read-only Windows SMB and folder metadata reporter for support review.
#>
[CmdletBinding()]
param([string]$Path='C:\Shares',[string]$OutputPath)
$RunStamp=Get-Date -Format 'yyyyMMdd_HHmmss'
if([string]::IsNullOrWhiteSpace($OutputPath)){$OutputPath=Join-Path ([Environment]::GetFolderPath('Desktop')) 'SMB_NTFS_Reports'}
New-Item -Path $OutputPath -ItemType Directory -Force|Out-Null
try{$shares=Get-SmbShare|Select-Object Name,Path,Description,Special,ContinuouslyAvailable;$shares|Export-Csv (Join-Path $OutputPath "smb_shares_$RunStamp.csv") -NoTypeInformation -Encoding UTF8}catch{$shares=@()}
$folders=@()
if(Test-Path $Path){$folders=Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue|Select-Object FullName,CreationTime,LastWriteTime,Attributes}
$folders|Export-Csv (Join-Path $OutputPath "folder_metadata_$RunStamp.csv") -NoTypeInformation -Encoding UTF8
$template='Confirm business owner','Confirm data classification','Confirm backup scope','Confirm expected access model','Confirm stale folders review','Confirm audit requirements'|ForEach-Object{[PSCustomObject]@{ReviewItem=$_;Status='Not assessed';Notes=''}}
$template|Export-Csv (Join-Path $OutputPath "storage_review_template_$RunStamp.csv") -NoTypeInformation -Encoding UTF8
$html="<h1>SMB NTFS Reporter - $env:COMPUTERNAME</h1><p>Generated $(Get-Date)</p><h2>Shares</h2>$($shares|ConvertTo-Html -Fragment)<h2>Folder Metadata</h2>$($folders|ConvertTo-Html -Fragment)"
$html|ConvertTo-Html -Title 'SMB NTFS Reporter'|Set-Content (Join-Path $OutputPath "smb_ntfs_report_$RunStamp.html") -Encoding UTF8
Write-Host "Reports saved to: $OutputPath" -ForegroundColor Green
Start-Process explorer.exe -ArgumentList "`"$OutputPath`"" -ErrorAction SilentlyContinue
