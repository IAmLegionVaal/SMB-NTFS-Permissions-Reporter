[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Path,
    [string]$Account,
    [ValidateSet('ReadAndExecute','Modify','FullControl','Write','Read')]
    [string]$Rights = 'Modify',
    [ValidateSet('Allow','Deny')]
    [string]$AccessControlType = 'Allow',
    [switch]$AddRule,
    [switch]$RemoveRule,
    [switch]$EnableInheritance,
    [string]$RestoreAclFrom,
    [switch]$DryRun,
    [switch]$Yes,
    [string]$OutputPath = (Join-Path $env:ProgramData 'SMBNTFSPermissionsRepair')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Failures = 0
$script:VerificationFailures = 0
$script:Actions = 0

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($env:OS -ne 'Windows_NT') { Write-Error 'This tool requires Windows.'; exit 3 }
if (-not (Test-Path -LiteralPath $Path)) { Write-Error "Path not found: $Path"; exit 2 }
$item = Get-Item -LiteralPath $Path -Force
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Write-Error 'Reparse points are not supported because the target can be ambiguous.'; exit 2 }
if (-not ($AddRule -or $RemoveRule -or $EnableInheritance -or $RestoreAclFrom)) { Write-Error 'Choose at least one repair action.'; exit 2 }
if (($AddRule -or $RemoveRule) -and [string]::IsNullOrWhiteSpace($Account)) { Write-Error '-Account is required for rule changes.'; exit 2 }
if ($AddRule -and $RemoveRule) { Write-Error 'Choose either -AddRule or -RemoveRule, not both.'; exit 2 }
if ($RestoreAclFrom -and -not (Test-Path -LiteralPath $RestoreAclFrom -PathType Leaf)) { Write-Error 'The ACL backup file was not found.'; exit 2 }
if (-not $DryRun -and -not (Test-Administrator)) { Write-Error 'Run from an elevated PowerShell session.'; exit 4 }

$runPath = Join-Path $OutputPath (Get-Date -Format 'yyyyMMdd_HHmmss')
$backupPath = Join-Path $runPath 'backup'
New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
$logPath = Join-Path $runPath 'repair.log'
$beforePath = Join-Path $runPath 'before.json'
$afterPath = Join-Path $runPath 'after.json'

function Write-Log([string]$Message) { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message" | Tee-Object -FilePath $logPath -Append }
function Invoke-RepairAction([string]$Description,[scriptblock]$Script) {
    $script:Actions++
    Write-Log "ACTION: $Description"
    if ($DryRun) { Write-Log "DRY-RUN: $Description"; return }
    try {
        $result = & $Script 2>&1
        if ($null -ne $result) { $result | Out-String | Add-Content $logPath }
        Write-Log "SUCCESS: $Description"
    } catch {
        $script:Failures++
        Write-Log "FAILED: $Description - $($_.Exception.Message)"
    }
}
function New-RequestedRule {
    $inheritance = if ($item.PSIsContainer) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $type = [Security.AccessControl.AccessControlType]::$AccessControlType
    [Security.AccessControl.FileSystemAccessRule]::new($Account,[Security.AccessControl.FileSystemRights]::$Rights,$inheritance,$propagation,$type)
}
function Get-RepairState {
    $acl = Get-Acl -LiteralPath $Path
    [pscustomobject]@{
        Collected = Get-Date
        Path = $item.FullName
        IsDirectory = $item.PSIsContainer
        Owner = $acl.Owner
        AreAccessRulesProtected = $acl.AreAccessRulesProtected
        Sddl = $acl.Sddl
        Access = @($acl.Access | Select-Object IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags,PropagationFlags)
    }
}

$before = Get-RepairState
$before | ConvertTo-Json -Depth 8 | Set-Content $beforePath -Encoding UTF8
$before | Export-Clixml (Join-Path $backupPath 'acl-state.xml')
$before.Sddl | Set-Content (Join-Path $backupPath 'acl.sddl') -Encoding ASCII

if (-not $DryRun -and -not $Yes) {
    if ((Read-Host 'Apply the selected NTFS permission repairs? Type YES') -cne 'YES') { Write-Log 'Repair cancelled.'; exit 10 }
}

if ($RestoreAclFrom) {
    Invoke-RepairAction "Restoring ACL on $Path from $RestoreAclFrom" {
        $sddl = (Get-Content -LiteralPath $RestoreAclFrom -Raw).Trim()
        $security = if ($item.PSIsContainer) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
        $security.SetSecurityDescriptorSddlForm($sddl)
        Set-Acl -LiteralPath $Path -AclObject $security
    }
}
if ($EnableInheritance) {
    Invoke-RepairAction "Enabling inherited permissions on $Path" {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($false,$true)
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
}
if ($AddRule) {
    Invoke-RepairAction "Adding $AccessControlType $Rights rule for $Account on $Path" {
        $acl = Get-Acl -LiteralPath $Path
        [void]$acl.AddAccessRule((New-RequestedRule))
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
}
if ($RemoveRule) {
    Invoke-RepairAction "Removing exact $AccessControlType $Rights rule for $Account on $Path" {
        $acl = Get-Acl -LiteralPath $Path
        if (-not $acl.RemoveAccessRuleSpecific((New-RequestedRule))) { throw 'The exact requested access rule was not found.' }
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
}

if (-not $DryRun) { Start-Sleep -Seconds 1 }
$after = Get-RepairState
$after | ConvertTo-Json -Depth 8 | Set-Content $afterPath -Encoding UTF8
if ($EnableInheritance -and $after.AreAccessRulesProtected) { $script:VerificationFailures++; Write-Log 'VERIFY FAILED: inheritance remains disabled.' }
if ($RestoreAclFrom) {
    $expectedSddl = (Get-Content -LiteralPath $RestoreAclFrom -Raw).Trim()
    if ($after.Sddl -ne $expectedSddl) { $script:VerificationFailures++; Write-Log 'VERIFY FAILED: restored SDDL does not match the supplied backup.' }
}
if ($AddRule -or $RemoveRule) {
    $matching = @($after.Access | Where-Object { $_.IdentityReference.ToString() -eq $Account -and $_.AccessControlType.ToString() -eq $AccessControlType -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::$Rights) -eq [Security.AccessControl.FileSystemRights]::$Rights }).Count -gt 0
    if (($AddRule -and -not $matching) -or ($RemoveRule -and $matching)) { $script:VerificationFailures++; Write-Log 'VERIFY FAILED: permission rule state does not match the requested action.' }
}

if ($script:Failures -gt 0) { exit 20 }
if ($script:VerificationFailures -gt 0) { exit 30 }
Write-Log "Repair completed. Actions: $script:Actions"
exit 0
