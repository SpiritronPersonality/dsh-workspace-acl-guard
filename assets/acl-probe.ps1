# Read-only ACL probe used by dsh-workspace-acl-guard.
#
# Input : -PathsBase64 <base64(UTF-8 JSON array of absolute paths)>
# Output: UTF-8 JSON array on stdout, one record per path:
#   path, exists, owner, ownerIsSelf, sddl, label, protected,
#   writeDac, writeOwner (true / false / null = unknown), role, error
#
# It NEVER writes a security descriptor.

param(
    [Parameter(Mandatory = $true)]
    [string]$PathsBase64,
    [switch]$IncludeKnown
)

$ErrorActionPreference = 'Stop'

$jsonText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($PathsBase64))
if ([string]::IsNullOrWhiteSpace($jsonText)) { $jsonText = '[]' }
$parsed = $jsonText | ConvertFrom-Json
if ($null -eq $parsed) { $paths = @() } else { $paths = @($parsed) }

$known = @{
    'desktop'           = [Environment]::GetFolderPath('Desktop')
    'documents'         = [Environment]::GetFolderPath('MyDocuments')
    'downloads'         = Join-Path $env:USERPROFILE 'Downloads'
    'pictures'          = [Environment]::GetFolderPath('MyPictures')
    'music'             = [Environment]::GetFolderPath('MyMusic')
    'videos'            = [Environment]::GetFolderPath('MyVideos')
    'start-menu'        = [Environment]::GetFolderPath('StartMenu')
    'startup'           = [Environment]::GetFolderPath('Startup')
    'onedrive'          = $env:OneDrive
    'profile-root'      = $env:USERPROFILE
    'windows'           = $env:SystemRoot
    'program-files'     = $env:ProgramFiles
    'program-files-x86' = ${env:ProgramFiles(x86)}
    'dsh-home'          = $(if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $env:USERPROFILE '.dsh' })
}

if ($IncludeKnown) {
    $extra = foreach ($value in $known.Values) {
        if (-not [string]::IsNullOrWhiteSpace($value) -and (Test-Path -LiteralPath $value)) { $value.TrimEnd('\') }
    }
    $paths = @($paths + $extra | Select-Object -Unique)
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

public static class DshAclProbe
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetNamedSecurityInfoW(string pObjectName, int ObjectType, uint SecurityInfo,
        IntPtr ppsidOwner, IntPtr ppsidGroup, IntPtr ppDacl, IntPtr ppSacl, out IntPtr ppSecurityDescriptor);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr pSD,
        uint RequestedStringSDRevision, uint SecurityInformation, out IntPtr StringSecurityDescriptor,
        out uint StringSecurityDescriptorLen);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    public static string ReadSddl(string path, out int writeDac, out int writeOwner, out string error)
    {
        writeDac = -1;
        writeOwner = -1;
        error = null;

        uint info = 0x15; // OWNER | DACL | SACL(LABEL)
        IntPtr sd = IntPtr.Zero;
        uint rc = GetNamedSecurityInfoW(path, 1, info, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out sd);
        if (rc != 0)
        {
            info = 0x5; // OWNER | DACL
            rc = GetNamedSecurityInfoW(path, 1, info, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out sd);
        }
        if (rc != 0)
        {
            error = "GetNamedSecurityInfoW=" + rc;
            return null;
        }

        string sddl = null;
        try
        {
            IntPtr text = IntPtr.Zero;
            uint length = 0;
            if (ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, info, out text, out length))
                sddl = Marshal.PtrToStringUni(text);
            else
                error = "ConvertSecurityDescriptorToStringSecurityDescriptorW=" + Marshal.GetLastWin32Error();
            if (text != IntPtr.Zero) LocalFree(text);

            if (sddl != null)
            {
                int dacWriteDac;
                int dacWriteOwner;
                if (TryEffectiveRights(sddl, out dacWriteDac, out dacWriteOwner))
                {
                    writeDac = dacWriteDac;
                    writeOwner = dacWriteOwner;
                }
            }
        }
        finally
        {
            LocalFree(sd);
        }
        return sddl;
    }

    private static bool TryEffectiveRights(string sddl, out int writeDac, out int writeOwner)
    {
        writeDac = -1;
        writeOwner = -1;
        try
        {
            int sacl = sddl.IndexOf("S:", StringComparison.Ordinal);
            string daclSddl = sacl >= 0 ? sddl.Substring(0, sacl) : sddl;
            if (daclSddl.Length == 0) daclSddl = "D:";

            RawSecurityDescriptor sd = new RawSecurityDescriptor(daclSddl);
            if (sd.DiscretionaryAcl == null)
            {
                writeDac = 1;
                writeOwner = 1;
                return true;
            }

            HashSet<string> sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            if (identity.User != null) sids.Add(identity.User.Value);
            if (identity.Groups != null)
                foreach (IdentityReference group in identity.Groups) sids.Add(group.Value);

            uint allowed = 0;
            uint denied = 0;
            foreach (GenericAce ace in sd.DiscretionaryAcl)
            {
                QualifiedAce qualified = ace as QualifiedAce;
                if (qualified == null) continue;
                if ((qualified.AceFlags & AceFlags.InheritOnly) != 0) continue;
                if (!sids.Contains(qualified.SecurityIdentifier.Value)) continue;

                uint mask = (uint)qualified.AccessMask;
                string type = qualified.AceType.ToString();
                if (type.IndexOf("Denied", StringComparison.Ordinal) >= 0) denied |= mask;
                else if (type.IndexOf("Allowed", StringComparison.Ordinal) >= 0) allowed |= mask;
            }

            const uint WRITE_DAC = 0x00040000;
            const uint WRITE_OWNER = 0x00080000;
            writeDac = (allowed & WRITE_DAC) != 0 && (denied & WRITE_DAC) == 0 ? 1 : 0;
            writeOwner = (allowed & WRITE_OWNER) != 0 && (denied & WRITE_OWNER) == 0 ? 1 : 0;
            return true;
        }
        catch
        {
            return false;
        }
    }
}
'@

function Get-LabelSid {
    param([string]$Sddl)
    $m = [regex]::Match($Sddl, 'S:[^(]*\(ML;[^;]*;[^;]*;;;([A-Za-z0-9]+)\)')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Get-Role {
    param([string]$Path, [hashtable]$Known)
    $p = $Path.TrimEnd('\')
    foreach ($key in $Known.Keys) {
        $value = $Known[$key]
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        $v = $value.TrimEnd('\')
        if ([string]::Equals($p, $v, [System.StringComparison]::OrdinalIgnoreCase)) { return $key }
    }
    $root = [System.IO.Path]::GetPathRoot($p)
    if ($root -and [string]::Equals($p, $root.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) { return 'drive-root' }
    if (Test-Path -LiteralPath (Join-Path $p '.git') -ErrorAction SilentlyContinue) { return 'repository' }
    $bin = Get-ChildItem -LiteralPath $p -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in '.exe', '.dll' } | Select-Object -First 1
    if ($null -ne $bin) { return 'application' }
    return 'directory'
}

$selfSid = $null
try { $selfSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch { }

$rows = foreach ($path in $paths) {
    $row = [ordered]@{
        path        = [string]$path
        exists      = $false
        owner       = $null
        ownerIsSelf = $null
        sddl        = $null
        label       = $null
        protected   = $null
        writeDac    = $null
        writeOwner  = $null
        role        = $null
        error       = $null
    }

    if (-not (Test-Path -LiteralPath $path)) {
        $row.error = 'not-found'
        [pscustomobject]$row
        continue
    }

    $row.exists = $true
    $row.role = Get-Role -Path $path -Known $known

    try {
        $writeDac = -1
        $writeOwner = -1
        $errorText = $null
        $sddl = [DshAclProbe]::ReadSddl($path, [ref]$writeDac, [ref]$writeOwner, [ref]$errorText)
        if ($null -eq $sddl) {
            $row.error = $errorText
        }
        else {
            $row.sddl = $sddl
            if ($writeDac -ge 0) { $row.writeDac = ($writeDac -eq 1) }
            if ($writeOwner -ge 0) { $row.writeOwner = ($writeOwner -eq 1) }
            $row.label = Get-LabelSid -Sddl $sddl

            $ownerMatch = [regex]::Match($sddl, '^O:(S-\d+(?:-\d+)+)')
            if ($ownerMatch.Success) {
                $row.owner = $ownerMatch.Groups[1].Value
                if ($null -ne $selfSid) { $row.ownerIsSelf = [string]::Equals($row.owner, $selfSid, [System.StringComparison]::OrdinalIgnoreCase) }
            }

            $daclMatch = [regex]::Match($sddl, 'D:([A-Z]*)')
            if ($daclMatch.Success) {
                $row.protected = $daclMatch.Groups[1].Value.Contains('P')
            }
        }
    }
    catch {
        $row.error = $_.Exception.Message
    }

    [pscustomobject]$row
}

$json = ConvertTo-Json -InputObject @($rows) -Depth 5 -Compress
$bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
$stdout = [Console]::OpenStandardOutput()
$stdout.Write($bytes, 0, $bytes.Length)
$stdout.Flush()
