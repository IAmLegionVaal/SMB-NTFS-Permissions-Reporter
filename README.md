# SMB NTFS Permissions Reporter

A PowerShell toolkit for Windows SMB and NTFS reporting with guarded, path-specific NTFS ACL repair.

## Diagnostic script

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\SMB_NTFS_Permissions_Reporter.ps1
```

The reporter remains read-only and exports share, folder and storage context for support review.

## Repair script

Preview a rule change:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\SMB_NTFS_Permissions_Repair_Toolkit.ps1 -Path 'D:\Shares\Finance' -Account 'CONTOSO\Finance Users' -Rights Modify -AddRule -DryRun
```

Examples:

```powershell
.\SMB_NTFS_Permissions_Repair_Toolkit.ps1 -Path 'D:\Shares\Finance' -Account 'CONTOSO\Finance Users' -Rights Modify -AddRule
.\SMB_NTFS_Permissions_Repair_Toolkit.ps1 -Path 'D:\Shares\Finance' -Account 'CONTOSO\Former Contractor' -Rights Modify -RemoveRule
.\SMB_NTFS_Permissions_Repair_Toolkit.ps1 -Path 'D:\Shares\Finance' -EnableInheritance
.\SMB_NTFS_Permissions_Repair_Toolkit.ps1 -Path 'D:\Shares\Finance' -RestoreAclFrom .\acl.sddl
```

## Repair behaviour

- Adds or removes one exact NTFS access rule for one selected file or directory.
- Supports `Read`, `ReadAndExecute`, `Write`, `Modify` and `FullControl` rights with `Allow` or `Deny` rules.
- Can re-enable inherited permissions or restore a supplied SDDL backup.
- Refuses reparse points to avoid changing an ambiguous target.
- Saves the complete original SDDL and ACL evidence before changes.
- Captures before-and-after owner, inheritance and access-rule state.
- Supports `-DryRun`, confirmation prompts or `-Yes`, administrator checks, logs and verification.

## Safety and exit codes

ACL changes can immediately affect access. Test effective permissions with both SMB share and NTFS layers in mind. The tool does not recursively rewrite child ACLs, change ownership, create accounts or alter SMB share permissions.

Exit codes: `0` success, `2` invalid arguments, `3` unsupported platform, `4` elevation required, `10` cancelled, `20` action failure and `30` verification failure.

## Validation note

The repair script was committed and statically reviewed, but it was not runtime-tested on a Windows file server.

## Author

Dewald Pretorius — L2 IT Support Engineer
