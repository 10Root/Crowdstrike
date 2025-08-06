<# 
#==============================
# CrowdStrike Identity Protection - Export Policy Match Events with Error Result
# ==============================
# By Adi Mahluf - 10root cyber security
# For any commens, please contant support@10root.com
# ======== CONFIGURE THESE ========
#>
$ClientID = "*******************************"
$ClientSecret = "********************************"
$Region = "US-1"  # Options: US-1, US-2, EU-1
$Duration = "P-1D"   # Relative ISO8601 (P-7D = last 7 days)
$OutputCSV = "C:\Temp\PolicyRuleErrors_24hr.csv"

# API URLs
switch ($Region.ToUpper()) {
    "US-1" {
        $TokenUrl = "https://api.crowdstrike.com/oauth2/token"
        $GraphQLUrl = "https://api.crowdstrike.com/identity-protection/combined/graphql/v1"
    }
    "US-2" {
        $TokenUrl = "https://api.us-2.crowdstrike.com/oauth2/token"
        $GraphQLUrl = "https://api.us-2.crowdstrike.com/identity-protection/combined/graphql/v1"
    }
    "EU-1" {
        $TokenUrl = "https://api.eu-1.crowdstrike.com/oauth2/token"
        $GraphQLUrl = "https://api.eu-1.crowdstrike.com/identity-protection/combined/graphql/v1"
    }
    default {
        Write-Error "Unsupported region: $Region"
        exit
    }
}

# ==============================

Write-Host "Getting OAuth token..."
$Body = @{
    client_id     = $ClientID
    client_secret = $ClientSecret
}
$TokenResponse = Invoke-RestMethod -Uri $TokenUrl -Method Post -Body $Body
$AccessToken = $TokenResponse.access_token

if (-not $AccessToken) {
    Write-Error "Failed to get access token. Check your credentials."
    exit
}

$Headers = @{
    "Authorization" = "Bearer $AccessToken"
    "Content-Type"  = "application/json"
}

# === Function to fetch policy match events ===
function Get-PolicyMatchEvents {
    param (
        [string]$AfterCursor = $null
    )

    $CursorPart = ""
    if ($AfterCursor) {
        $CursorPart = "after: `"$AfterCursor`""
    }

    $GraphQL = @"
{
  timeline(
    types: [POLICY_RULE_MATCH]
    startTime: "$Duration"
    sortOrder: DESCENDING
    first: 100
    $CursorPart
  ) {
    nodes {
      timestamp
      eventType
      ... on TimelinePolicyRuleMatchEvent {
        ruleName
        ruleId
        triggerLabel
        sourceEndpointDisplayName
        sourceEntity { primaryDisplayName }
        targetEntity { primaryDisplayName }
        resultDescription
        successful
        actionLabel
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"@

    $Body = @{ query = $GraphQL } | ConvertTo-Json -Depth 5
    return Invoke-RestMethod -Uri $GraphQLUrl -Method Post -Headers $Headers -Body $Body
}

# === Collect all pages and filter for "Error" ===
$AllEvents = @()
$NextCursor = $null

do {
    Write-Host "Fetching policy match events page..."
    $Response = Get-PolicyMatchEvents -AfterCursor $NextCursor
    $Nodes = $Response.data.timeline.nodes

    $Filtered = $Nodes | Where-Object {
        $_.resultDescription -and $_.resultDescription -match 'error'
    }

    $Filtered | ForEach-Object {
        $AllEvents += [PSCustomObject]@{
            Timestamp       = $_.timestamp
            RuleName        = $_.ruleName
            RuleID          = $_.ruleId
            TriggerLabel    = $_.triggerLabel
            SourceEntity    = $_.sourceEntity.primaryDisplayName
            TargetEntity    = $_.targetEntity.primaryDisplayName
            SourceEndpoint  = $_.sourceEndpointDisplayName
            Result          = $_.resultDescription
            ActionLabel     = $_.actionLabel
            Successful      = $_.successful
        }
    }

    $HasNext = $Response.data.timeline.pageInfo.hasNextPage
    $NextCursor = $Response.data.timeline.pageInfo.endCursor
} while ($HasNext)

# === Output ===
if ($AllEvents.Count -eq 0) {
    Write-Warning "No POLICY_RULE_MATCH events with result containing 'Error' found in last $Duration."
} else {
    Write-Host "Found $($AllEvents.Count) policy match events with result containing 'Error'."
    $AllEvents | Format-Table -AutoSize
    $AllEvents | Export-Csv -Path $OutputCSV -NoTypeInformation
    Write-Host "`nFiltered results exported to: $OutputCSV"
}
