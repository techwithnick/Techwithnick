<#
.SYNOPSIS
  Webhook-driven Group Factory (Commercial/Global Azure) — idempotent create + strong verification/backoff.

.BODY (JSON posted to webhook)
  {
    "Prefix":"Test",
    "Cloud":"AZ",
    "Level":"4",
    "Env":"D",
    "Role":"Owner",
    "Owners":["owner@contoso.com"],     // optional
    "Members":["member@contoso.com"],   // optional
    "EnablePIM": false                  // optional (PIM stub)
  }
#>

param(
  [Parameter(Mandatory=$false)]
  [object]$WebhookData,

  [ValidateSet('Global','USGov','USGovDoD')]
  [string]$GraphEnvironment = 'Global'
)

# =========================== Logging / Step Helpers ===========================
$script:STEP = 0
function Write-Log {
  param(
    [string]$Message,
    [ValidateSet('INFO','WARN','ERROR','DEBUG','STEP','OK')]$Level='INFO'
  )
  $ts=(Get-Date).ToString('s')
  $prefix = switch($Level){ 'STEP' {'[STEP]'} 'OK' {'[ OK ]'} default {"[$Level]"} }
  Write-Output ("{0} {1} {2}" -f $ts,$prefix,$Message)
}
function Start-Step { param([string]$Msg) $script:STEP++; Write-Log ("{0}. {1}" -f $script:STEP,$Msg) 'STEP' }
function Ok   { param([string]$Msg) Write-Log $Msg 'OK' }
function Warn { param([string]$Msg) Write-Log $Msg 'WARN' }
function Fail { param([string]$Msg) Write-Log $Msg 'ERROR' }
function Stop-BadRequest { param([string]$Msg) Fail $Msg; throw $Msg }
function Try-Step {
  param(
    [Parameter(Mandatory)][scriptblock]$Do,
    [string]$OnSuccess="Success",
    [string]$OnErrorWarn="Operation failed",
    [switch]$ThrowOnError
  )
  try { $r = & $Do; Ok $OnSuccess; return $r }
  catch {
    if ($ThrowOnError){ Fail ("{0}. Details: {1}" -f $OnErrorWarn, ($_.Exception.Message)); throw }
    else { Warn ("{0}. Details: {1}" -f $OnErrorWarn, ($_.Exception.Message)); return $null }
  }
}

# =========================== Role Policy (for future PIM) =====================
$AzRolePolicies = @{
  'Owner'       = @{ Cloud='AZ';  PermanentEligible=$true; Approval=$true;  ApproverGroup='US Navy'; Duration='PT1H' }
  'Contributor' = @{ Cloud='AZ';  PermanentEligible=$true; Approval=$false; ApproverGroup=$null;     Duration='PT4H' }
  'DBAdmin'     = @{ Cloud='AZ';  PermanentEligible=$true; Approval=$false; ApproverGroup=$null;     Duration='PT4H' }
  'DevOps'      = @{ Cloud='AZ';  PermanentEligible=$true; Approval=$false; ApproverGroup=$null;     Duration='PT4H' }
  'CostMGMT'    = @{ Cloud='AZ';  PermanentEligible=$true; Approval=$false; ApproverGroup=$null;     Duration='PT4H' }
}
$AwsRolePolicies = @{
  'Admin'   = @{ Cloud='AWS'; PermanentEligible=$true; Approval=$true;  ApproverGroup='US Navy'; Duration='PT1H' }
  'SysAdmin'= @{ Cloud='AWS'; PermanentEligible=$true; Approval=$false; ApproverGroup=$null;     Duration='PT4H' }
  'DBAdmin' = @{ Cloud='AWS'; PermanentEligible=$true; Approval=$false; ApproverGroup=$null;     Duration='PT4H' }
  'DevOps'  = @{ Cloud='AWS'; PermanentEligible=$true; Approval=$false; ApproverGroup=$null;     Duration='PT4H' }
  'CostMGMT'= @{ Cloud='AWS'; PermanentEligible=$true; Approval=$false; ApproverGroup=$null;     Duration='PT4H' }
}
function Get-RolePolicy {
  param([string]$Cloud,[string]$Role)
  if ($Cloud -eq 'AZ') { return $AzRolePolicies[$Role] } else { return $AwsRolePolicies[$Role] }
}

# =========================== Allowed Inputs ===================================
$AllowedPrefixes   = @('Test')
$AllowedClouds     = @('AZ','AWS','AWSIL2','AWSIL45')
$AllowedLevels     = @('2','4','5')
$AllowedEnvLetters = @('D','T','P')
$AzureRoles        = @('CG_Owner','CG_Contributor','CG_DBAdmin','CG_DevOps','CG_CostMGMT')
$AwsRoles          = @('Admin','SysAdmin','DBAdmin','DevOps','CostMGMT')

# =========================== Config to EDIT ===================================
$EnterpriseAppsByPrefix = @{
  'Test' = 'AWS IAM Identity Center (successor to AWS Single Sign-On)'  # <-- EDIT if needed
}
$DefaultAwsAppRoleId = [guid]'#INPUTGUID'    # <-- EDIT to your actual GUID

# =========================== Graph Utilities & Helpers ========================
function Get-GroupByName {
  param([Parameter(Mandatory)][string]$GroupName)
  Get-MgGroup -Filter "displayName eq '$GroupName'" -ConsistencyLevel eventual -Count x -ErrorAction Stop
}

function Get-UserIdByUpn {
  param([string]$Upn)
  $res = Get-MgUser -Filter "userPrincipalName eq '$Upn'" -ConsistencyLevel eventual -Count c -ErrorAction SilentlyContinue
  $arr = @($res)
  if ($arr.Count -gt 0 -and $arr[0].Id) { return $arr[0].Id }
  return $null
}

# read-after-write verifier with retry/backoff (tries by Id first, then by name)
function Wait-ForGroup {
  param(
    [string]$GroupId,
    [string]$GroupName,
    [int]$TimeoutSec = 45
  )
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $delay = 1
  while ((Get-Date) -lt $deadline) {
    try {
      if ($GroupId -and $GroupId -match '^[0-9a-fA-F-]{36}$') {
        $g = Get-MgGroup -GroupId $GroupId -ErrorAction Stop
        if ($g -and $g.Id) { return $g }
      } else {
        $q = Get-MgGroup -Filter "displayName eq '$GroupName'" -ConsistencyLevel eventual -Count x -ErrorAction Stop
        $arr = @($q) | Where-Object { $_.DisplayName -eq $GroupName -and $_.Id }
        if ($arr.Count -gt 0) { return $arr[0] }
      }
    } catch { }
    Write-Log ("Verify retry in {0}s..." -f $delay) 'DEBUG'
    Start-Sleep -Seconds $delay
    $delay = [Math]::Min($delay * 2, 8)  # 1,2,4,8 capped
  }
  return $null
}

# Idempotent create: return existing if found; on conflict, resolve existing instead of creating a duplicate
function Ensure-Group {
  param(
    [Parameter(Mandatory)][string]$GroupName,
    [Parameter(Mandatory)][string]$MailNickname
  )

  Start-Step ("ensure group '{0}'" -f $GroupName)
  # 1) check existence first
  $existing = Try-Step { Get-GroupByName -GroupName $GroupName } -OnSuccess "$GroupName lookup completed"
  $match    = @($existing) | Where-Object { $_.DisplayName -eq $GroupName -and $_.Id } | Select-Object -First 1
  if ($match) {
    Ok ("exists | Id={0}" -f $match.Id)
    return [string]$match.Id
  }

  # 2) create (idempotent)
  Write-Log ("creating group '{0}'" -f $GroupName) 'INFO'
  $body = @{
    displayName     = $GroupName
    mailEnabled     = $false
    mailNickname    = $MailNickname
    securityEnabled = $true
    groupTypes      = @()
  }
  try {
    $newGrp = New-MgGroup -BodyParameter $body -ErrorAction Stop
    Ok ("created | Id={0}" -f $newGrp.Id)
    return [string]$newGrp.Id
  } catch {
    $msg = $_.Exception.Message
    # Common Graph conflict patterns
    if ($msg -match 'ObjectConflict' -or
        $msg -match 'same value for property mailNickname' -or
        $msg -match 'already exists') {
      Warn "create returned conflict; resolving existing object…"
      # Try to resolve by name with backoff (read-after-write / index lag / previous run)
      $resolved = Wait-ForGroup -GroupId $null -GroupName $GroupName -TimeoutSec 45
      if ($resolved -and $resolved.Id) {
        Ok ("using existing group | Id={0}" -f $resolved.Id)
        return [string]$resolved.Id
      } else {
        throw "Conflict reported but group not resolvable by name. Investigate duplicate nickname in tenant."
      }
    }
    throw
  }
}

function Ensure-OwnersMembers {
  param([string]$GroupId,[string[]]$Owners,[string[]]$Members,[string]$GraphV1)
  if (($Owners -and $Owners.Count -gt 0) -or ($Members -and $Members.Count -gt 0)) { Start-Step "processing owners/members" }

  foreach ($o in ($Owners | Where-Object { $_ -and $_.Trim() })) {
    $oid = Get-UserIdByUpn -Upn $o
    if ($oid) {
      Write-Log "Adding owner: $o ($oid)"
      Try-Step { Add-MgGroupOwnerByRef -GroupId $GroupId -BodyParameter @{ '@odata.id'="$GraphV1/directoryObjects/$oid" } -ErrorAction Stop } `
        -OnSuccess "Owner added" -OnErrorWarn "Owner add failed: $o"
    } else { Warn "Owner not found: $o" }
  }
  foreach ($m in ($Members | Where-Object { $_ -and $_.Trim() })) {
    $mid = Get-UserIdByUpn -Upn $m
    if ($mid) {
      Write-Log "Adding member: $m ($mid)"
      Try-Step { Add-MgGroupMemberByRef -GroupId $GroupId -BodyParameter @{ '@odata.id'="$GraphV1/directoryObjects/$mid" } -ErrorAction Stop } `
        -OnSuccess "Member added" -OnErrorWarn "Member add failed: $m"
    } else { Warn "Member not found: $m" }
  }
}

# =========================== Azure RBAC (Stub) ================================
function Ensure-AzRoleAssignment {
  param([string]$GroupId,[string]$GroupName,[string]$RoleName)
  Start-Step ("checking if {0} assignment exists on {1}" -f $RoleName,$GroupName)
  Ok ("[stub] Would ensure Azure RBAC: {0} on {1}" -f $RoleName,$GroupName)
}

# =========================== AWS Enterprise App (hardcoded appRoleId) =========
function Check-AppRoleAssignmentExists {
  param([string]$ServicePrincipalId,[string]$GroupId,[Guid]$AppRoleId)
  $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalId -ErrorAction SilentlyContinue |
              Where-Object { $_.PrincipalId -eq $GroupId -and $_.AppRoleId -eq $AppRoleId }
  return ($null -ne $existing -and $existing.Count -gt 0)
}
function Ensure-AwsAppAssignment {
  param([string]$GroupId,[string]$GroupName,[string]$EntAppIdOrName,[string]$GraphV1)

  $sp = Try-Step {
    (Get-MgServicePrincipal -Filter "appId eq '$EntAppIdOrName' or displayName eq '$EntAppIdOrName'" -ErrorAction Stop)[0]
  } -OnSuccess "Enterprise application resolved" -OnErrorWarn "Unable to resolve Enterprise Application"
  if (-not $sp) { return }
  $spId = $sp.Id
  $appRoleId = $DefaultAwsAppRoleId

  Start-Step ("checking if {0} is assigned to enterprise application {1}" -f $GroupName,$sp.DisplayName)
  $has = Try-Step {
    Check-AppRoleAssignmentExists -ServicePrincipalId $spId -GroupId $GroupId -AppRoleId $appRoleId
  } -OnSuccess "Enterprise app assignment check complete" -OnErrorWarn "Unable to check enterprise app assignment"
  if ($null -eq $has) { return }

  if ($has) {
    Ok ("{0} already assigned to {1}" -f $GroupName,$sp.DisplayName)
  } else {
    Start-Step ("assigning {0} to enterprise app {1} (AppRoleId={2})" -f $GroupName,$sp.DisplayName,$appRoleId)
    Try-Step {
      New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId -BodyParameter @{
        principalId = $GroupId
        resourceId  = $spId
        appRoleId   = $appRoleId
      } -ErrorAction Stop
    } -OnSuccess "Enterprise application assignment created" -OnErrorWarn "Failed to assign enterprise application" -ThrowOnError
  }
}

# =========================== PIM Stubs =======================================
function Check-PimPolicy {
  param([string]$GroupId,[string]$Cloud)
  throw "License or permission not configured"
}
function Ensure-PimPolicy {
  param([string]$GroupId,[string]$GroupName,[string]$Cloud,[object]$Policy)
  if ($Policy -is [System.Array]) { $Policy = $Policy | Select-Object -First 1 }
  if (-not ($Policy -is [System.Collections.IDictionary])) { Write-Log "PIM: No usable policy; skipping." 'WARN'; return }
  Start-Step ("checking existing PIM policy on ({0}) {1}" -f $Cloud,$GroupName)
  $policy = Try-Step { Check-PimPolicy -GroupId $GroupId -Cloud $Cloud } -OnSuccess "PIM policy lookup complete" -OnErrorWarn "Unable to check PIM policy"
  if ($null -eq $policy) { return }
  if (-not $policy) {
    Start-Step ("creating PIM policy per role requirements")
    Ok "PIM policy created (stub)"
  } else { Ok ("PIM policy found on {0}" -f $GroupName) }
}

# =========================== Main ============================================
try {
  Start-Step "parsing payload"
  if (-not $WebhookData) { Stop-BadRequest "No WebhookData received. POST JSON to the webhook." }

  $payload = if ($WebhookData.RequestBody) {
    if ($WebhookData.RequestBody -is [string]) { $WebhookData.RequestBody | ConvertFrom-Json } else { $WebhookData.RequestBody }
  } else { $WebhookData | ConvertFrom-Json }
  if (-not $payload) { Stop-BadRequest "Empty payload." }

  # Normalize inputs
  $Prefix    = ([string]$payload.Prefix).Trim()
  $Cloud     = ([string]$payload.Cloud).Trim()
  $Level     = ([string]$payload.Level).Trim()
  $Env       = ([string]$payload.Env).Trim()
  $Role      = ([string]$payload.Role).Trim()
  $Owners    = @($payload.Owners)
  $Members   = @($payload.Members)
  $EnablePIM = if ($payload.PSObject.Properties.Name -contains 'EnablePIM') { [bool]$payload.EnablePIM } else { $false }

  Ok ("Payload OK: Prefix={0} Cloud={1} Level={2} Env={3} Role={4} EnablePIM={5}" -f $Prefix,$Cloud,$Level,$Env,$Role,$EnablePIM)

  # Validate menus
  Start-Step "validating inputs"
  if ($Prefix -notin $AllowedPrefixes)         { Stop-BadRequest "Prefix not allowed: $Prefix" }
  if ($Cloud  -notin $AllowedClouds)           { Stop-BadRequest "Cloud not allowed: $Cloud" }
  if ($Level  -notin $AllowedLevels)           { Stop-BadRequest "Level not allowed: $Level" }
  if ($Env    -notin $AllowedEnvLetters)       { Stop-BadRequest "Env must be D/T/P; got: $Env" }

  $isAzure = ($Cloud -eq 'AZ'); $isAws = (-not $isAzure)
  if ($isAzure -and $Role -notin $AzureRoles)  { Stop-BadRequest "Role '$Role' not valid for Azure cloud." }
  if ($isAws   -and $Role -notin $AwsRoles)    { Stop-BadRequest "Role '$Role' not valid for AWS clouds." }
  Ok "Inputs validated"

  # Build names
  Start-Step "building group name and alias"
  $groupName = "{0}-{1}{2}{3}-{4}" -f $Prefix,$Cloud,$Level,$Env,$Role
  $mailNick  = ($groupName.ToLower() -replace '[^a-z0-9]+','-').Trim('-')
  Ok ("Target Group: {0} | MailNickname: {1}" -f $groupName,$mailNick)

  # Connect Graph
  Start-Step "connecting to Microsoft Graph ($GraphEnvironment)"
  Connect-MgGraph -Identity -Environment $GraphEnvironment -NoWelcome
  $ctx = Get-MgContext
  Ok ("Connected. Tenant={0} ClientId={1} Env={2}" -f $ctx.TenantId,$ctx.ClientId,$ctx.Environment)

  $GraphBase = switch ($GraphEnvironment) {
    'Global'   { 'https://graph.microsoft.com' }
    'USGov'    { 'https://graph.microsoft.us' }
    'USGovDoD' { 'https://dod-graph.microsoft.us' }
  }
  $GraphV1 = "$GraphBase/v1.0"
  Write-Log "[DEBUG] GraphV1=$GraphV1" 'DEBUG'

  # Step 5: idempotent ensure/create
  Start-Step ("ensuring/creating group '{0}'" -f $groupName)
  $groupId = Ensure-Group -GroupName $groupName -MailNickname $mailNick

  # Step 6: verify with backoff (handles read-after-write lag)
  Start-Step "verifying group presence (with backoff)"
  $resolved = Wait-ForGroup -GroupId $groupId -GroupName $groupName -TimeoutSec 45
  if ($resolved -and $resolved.Id) {
    $groupId = [string]$resolved.Id
    Ok ("Verified. Group exists: Name={0} Id={1}" -f $resolved.DisplayName,$groupId)
  } else {
    Warn "Verification timed out — group likely exists; Graph not yet consistent. Re-check shortly."
  }

  # Owners/Members (safe lookups)
  if (($Owners -and $Owners.Count -gt 0) -or ($Members -and $Members.Count -gt 0)) {
    Ensure-OwnersMembers -GroupId $groupId -Owners $Owners -Members $Members -GraphV1 $GraphV1
  }

  # Branching
  $rolePolicy = Get-RolePolicy -Cloud ($isAzure ? 'AZ' : 'AWS') -Role $Role
  if ($isAzure) {
    Ensure-AzRoleAssignment -GroupId $groupId -GroupName $groupName -RoleName $Role
    if ($EnablePIM -and ($rolePolicy -is [System.Collections.IDictionary])) {
      Ensure-PimPolicy -GroupId $groupId -GroupName $groupName -Cloud 'AZ' -Policy $rolePolicy
    } else { Write-Log "PIM step skipped (EnablePIM=$EnablePIM or policy missing)." 'WARN' }
  } else {
    if (-not $EnterpriseAppsByPrefix.ContainsKey($Prefix)) { Stop-BadRequest "No Enterprise App mapping for Prefix '$Prefix'" }
    Ensure-AwsAppAssignment -GroupId $groupId -GroupName $groupName -EntAppIdOrName $EnterpriseAppsByPrefix[$Prefix] -GraphV1 $GraphV1
    if ($EnablePIM -and ($rolePolicy -is [System.Collections.IDictionary])) {
      Ensure-PimPolicy -GroupId $groupId -GroupName $groupName -Cloud 'AWS' -Policy $rolePolicy
    } else { Write-Log "PIM step skipped (EnablePIM=$EnablePIM or policy missing)." 'WARN' }
  }

  Ok ("DONE. Name='{0}' Id='{1}' EnablePIM={2}" -f $groupName,$groupId,$EnablePIM)

  # Return a compact result
  [pscustomobject]@{
    GroupName = $groupName
    GroupId   = $groupId
    Cloud     = $Cloud
    Level     = $Level
    Role      = $Role
    EnablePIM = $EnablePIM
  } | ConvertTo-Json -Depth 5

} catch {
  $err = ($_ | Out-String).Trim()
  Fail "FATAL: $err"
  throw
}
