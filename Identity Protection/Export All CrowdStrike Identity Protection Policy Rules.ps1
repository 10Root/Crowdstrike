#====================================
# Export All CrowdStrike Identity Protection Policy Rules
# Author: Adi Mahluf — 10root Cyber Security
# Summary: Exports all configured Crowdstrike Identity Protection policy rules to a CSV file.
# Prerequisite: API permission — Identity Protection Policy Rules (Read).
# Last Updated: 2025-09-10
#
# Known Issues / Limitations:
# 1. Currently, the only supported trigger is "access" due to a CrowdStrike API limitation.
# 2. Usernames and endpoints are displayed as IDs rather than sAMAccountName / UPN / display name; this is expected at this time.
# 3. The "CreatedAt" attribute reflects the report creation time, not the rule creation time; this behavior is under investigation.
#====================================

# ======== Configure your parameters ======== #
$ClientID = "*******************************" # Your CrowdStrike API Client ID
$ClientSecret = "****************************************" # Your CrowdStrike API Client Secret
$Region = "US-1" # Options: US-1, US-2, EU-1
$OutputCSV = "C:\10root\IdentityProtectionPolicies.csv" # Path for CSV export
$DebugPreference = "Continue" # Set to "SilentlyContinue" to suppress debug output

# ======== Set TLS 1.2 ======== #
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ======== API URLs ======== #
switch ($Region.ToUpper()) {
    "US-1" {
        $TokenUrl = "https://api.crowdstrike.com/oauth2/token"
        $PolicyRulesQueryUrl = "https://api.crowdstrike.com/identity-protection/queries/policy-rules/v1"
        $PolicyRulesDetailsUrl = "https://api.crowdstrike.com/identity-protection/entities/policy-rules/v1"
        $GraphQLUrl = "https://api.crowdstrike.com/identity-protection/combined/graphql/v1"
    }
    "US-2" {
        $TokenUrl = "https://api.us-2.crowdstrike.com/oauth2/token"
        $PolicyRulesQueryUrl = "https://api.us-2.crowdstrike.com/identity-protection/queries/policy-rules/v1"
        $PolicyRulesDetailsUrl = "https://api.us-2.crowdstrike.com/identity-protection/entities/policy-rules/v1"
        $GraphQLUrl = "https://api.us-2.crowdstrike.com/identity-protection/combined/graphql/v1"
    }
    "EU-1" {
        $TokenUrl = "https://api.eu-1.crowdstrike.com/oauth2/token"
        $PolicyRulesQueryUrl = "https://api.eu-1.crowdstrike.com/identity-protection/queries/policy-rules/v1"
        $PolicyRulesDetailsUrl = "https://api.eu-1.crowdstrike.com/identity-protection/entities/policy-rules/v1"
        $GraphQLUrl = "https://api.eu-1.crowdstrike.com/identity-protection/combined/graphql/v1"
    }
    default {
        Write-Error "Unsupported region: $Region. Use US-1, US-2, or EU-1."
        exit
    }
}

# ======== Validate URLs ======== #
Write-Debug "Token URL: $TokenUrl"
Write-Debug "Policy Rules Query URL: $PolicyRulesQueryUrl"
Write-Debug "Policy Rules Details URL: $PolicyRulesDetailsUrl"
Write-Debug "GraphQL URL: $GraphQLUrl"

if (-not $PolicyRulesDetailsUrl -or -not $GraphQLUrl) {
    Write-Error "One or more API URLs are empty. Check region configuration."
    exit
}

# ======== Get OAuth Token ======== #
Write-Host "Getting OAuth token..."
$Body = @{
    client_id     = $ClientID
    client_secret = $ClientSecret
}
try {
    $TokenResponse = Invoke-RestMethod -Uri $TokenUrl -Method Post -Body $Body
    $AccessToken = $TokenResponse.access_token
}
catch {
    Write-Error "Failed to get access token. Error: $_"
    exit
}

if (-not $AccessToken) {
    Write-Error "No access token received. Check your credentials."
    exit
}

$Headers = @{
    "Authorization" = "Bearer $AccessToken"
    "Content-Type"  = "application/json"
}

# ======== Function to Fetch Policy Rule IDs ======== #
function Get-PolicyRuleIds {
    param (
        [string]$Offset = ""
    )

    $QueryUrl = $PolicyRulesQueryUrl
    if ($Offset) {
        $QueryUrl += "?offset=$Offset"
    }

    Write-Debug "Fetching rule IDs from: $QueryUrl"
    try {
        $Response = Invoke-RestMethod -Uri $QueryUrl -Method Get -Headers $Headers
        return $Response
    }
    catch {
        Write-Error "Failed to fetch policy rule IDs. Error: $_"
        return $null
    }
}

# ======== Function to Fetch Policy Rule Details ======== #
function Get-PolicyRuleDetails {
    param (
        [string]$RuleId
    )

    if (-not $RuleId) {
        Write-Error "RuleId is empty or null."
        return $null
    }

    $DetailsUrl = "${PolicyRulesDetailsUrl}?ids=$RuleId"

    Write-Debug "Fetching details for Rule ID: $RuleId"
    Write-Debug "Constructed URL: $DetailsUrl"
    try {
        $Response = Invoke-RestMethod -Uri $DetailsUrl -Method Get -Headers $Headers
        Write-Debug "Response: $($Response | ConvertTo-Json -Depth 5)"
        return $Response
    }
    catch {
        Write-Error "Failed to fetch policy rule details for ID: $RuleId. Error: $_"
        return $null
    }
}

# ======== Function to Resolve Entity IDs to Names via GraphQL ======== #
function Get-EntityNames {
    param (
        [string[]]$EntityIds,
        [string]$EntityType # user, endpoint, destination
    )

    if (-not $EntityIds) {
        Write-Debug "No ${EntityType} IDs provided for resolution."
        return @{}
    }

    $NameMap = @{}
    # Split IDs into batches of 50 to avoid API limits
    $BatchSize = 50
    $Batches = for ($i = 0; $i -lt $EntityIds.Count; $i += $BatchSize) {
        $EntityIds[$i..($i + $BatchSize - 1)]
    }

    foreach ($Batch in $Batches) {
        $QueryTemplate = @"
query {
  entities(ids: ["$($Batch -join '","')"]) {
    nodes {
      id
      ... on UserEntity {
        samaccountname
        upn
        primaryDisplayName
      }
      ... on EndpointEntity {
        primaryDisplayName
      }
      ... on ApplicationEntity {
        primaryDisplayName
      }
    }
  }
}
"@

        $Body = @{
            query = $QueryTemplate
        } | ConvertTo-Json -Depth 10

        Write-Host "--- Debug: Sending GraphQL query for ${EntityType} IDs ---"
        Write-Host "Query: $($QueryTemplate)"
        try {
            $Response = Invoke-RestMethod -Uri $GraphQLUrl -Method Post -Headers $Headers -Body $Body
            Write-Host "--- Debug: Received GraphQL response for ${EntityType} IDs ---"
            Write-Host "Response: $($Response | ConvertTo-Json -Depth 5)"
            Write-Host "--------------------------------------------------------"

            foreach ($Node in $Response.data.entities.nodes) {
                $Name = if ($EntityType -eq "user") {
                    if ($Node.samaccountname) {
                        $Node.samaccountname
                    }
                    elseif ($Node.upn) {
                        $Node.upn
                    }
                    elseif ($Node.primaryDisplayName) {
                        $Node.primaryDisplayName
                    }
                }
                else {
                    $Node.primaryDisplayName
                }
                if ($Name) {
                    $NameMap[$Node.id] = $Name
                }
            }
        }
        catch {
            Write-Error "Failed to resolve ${EntityType} IDs: $($Batch -join ','). Error: $_"
        }
    }
    return $NameMap
}

# ======== Step 1: Fetch All Policy Rule IDs ======== #
Write-Host "Fetching all policy rule IDs..."
$AllRuleIds = @()
$Offset = ""
do {
    $QueryResponse = Get-PolicyRuleIds -Offset $Offset
    if (-not $QueryResponse) {
        Write-Error "Failed to retrieve policy rule IDs. Exiting."
        exit
    }

    $AllRuleIds += $QueryResponse.resources
    $Offset = $QueryResponse.meta.pagination.offset
} while ($QueryResponse.meta.pagination.next)

if (-not $AllRuleIds) {
    Write-Warning "No policy rules found in the system."
    exit
}

Write-Host "Found $($AllRuleIds.Count) policy rules: $AllRuleIds"

# ======== Step 2: Fetch Details for All Rules ======== #
Write-Host "Fetching policy rule details..."
$AllRules = @()
foreach ($RuleId in $AllRuleIds) {
    Write-Host "Processing rule ID: $RuleId..."
    $DetailsResponse = Get-PolicyRuleDetails -RuleId $RuleId
    if ($DetailsResponse -and $DetailsResponse.resources) {
        $AllRules += $DetailsResponse.resources
    }
}

if (-not $AllRules) {
    Write-Warning "No policy rule details retrieved."
    exit
}

# ======== Step 3: Resolve Entity Names ======== #
Write-Host "Resolving entity names..."

# Collect all unique IDs for batch resolution
$AllUserIds = @()
$AllEndpointIds = @()
$AllDestinationIds = @()

foreach ($Rule in $AllRules) {
    if ($Rule.ruleConditions.sourceUser.entityId.options) {
        $AllUserIds += $Rule.ruleConditions.sourceUser.entityId.options.PSObject.Properties | Where-Object { $_.Value -eq "INCLUDED" } | ForEach-Object { $_.Name }
    }
    if ($Rule.ruleConditions.sourceEndpoint.entityId.options) {
        $AllEndpointIds += $Rule.ruleConditions.sourceEndpoint.entityId.options.PSObject.Properties | Where-Object { $_.Value -eq "INCLUDED" } | ForEach-Object { $_.Name }
    }
    if ($Rule.ruleConditions.destination.entityId.options) {
        $AllDestinationIds += $Rule.ruleConditions.destination.entityId.options.PSObject.Properties | Where-Object { $_.Value -eq "INCLUDED" } | ForEach-Object { $_.Name }
    }
}

$AllUserIds = $AllUserIds | Select-Object -Unique
$AllEndpointIds = $AllEndpointIds | Select-Object -Unique
$AllDestinationIds = $AllDestinationIds | Select-Object -Unique

# Resolve names via GraphQL
$UserNameMap = Get-EntityNames -EntityIds $AllUserIds -EntityType "user"
$EndpointNameMap = Get-EntityNames -EntityIds $AllEndpointIds -EntityType "endpoint"
$DestinationNameMap = Get-EntityNames -EntityIds $AllDestinationIds -EntityType "destination"

# ======== Step 4: Format and Export to CSV ======== #
Write-Host "Formatting policy rules for export..."
$FormattedRules = $AllRules | ForEach-Object {
    # Extract key fields
    $SourceUserNames = if ($_.ruleConditions.sourceUser.entityId.options) {
        ($_.ruleConditions.sourceUser.entityId.options.PSObject.Properties |
            Where-Object { $_.Value -eq "INCLUDED" } |
            ForEach-Object {
                if ($UserNameMap[$_.Name]) {
                    $UserNameMap[$_.Name]
                } else {
                    $_.Name
                }
            }) -join ","
    } else { "" }

    $SourceEndpointNames = if ($_.ruleConditions.sourceEndpoint.entityId.options) {
        ($_.ruleConditions.sourceEndpoint.entityId.options.PSObject.Properties |
            Where-Object { $_.Value -eq "INCLUDED" } |
            ForEach-Object {
                if ($EndpointNameMap[$_.Name]) {
                    $EndpointNameMap[$_.Name]
                } else {
                    $_.Name
                }
            }) -join ","
    } else { "" }

    $DestinationNames = if ($_.ruleConditions.destination.entityId.options) {
        ($_.ruleConditions.destination.entityId.options.PSObject.Properties |
            Where-Object { $_.Value -eq "INCLUDED" } |
            ForEach-Object {
                if ($DestinationNameMap[$_.Name]) {
                    $DestinationNameMap[$_.Name]
                } else {
                    $_.Name
                }
            }) -join ","
    } else { "" }

    $AccessTypes = if ($_.ruleConditions.activity.accessType.options) {
        ($_.ruleConditions.activity.accessType.options.PSObject.Properties | Where-Object { $_.Value -eq "INCLUDED" } | ForEach-Object { $_.Name }) -join ","
    } else { "" }

    # Handle Trigger field
    $Trigger = ""
    if ($_.ruleConditions | Where-Object { $_.trigger } | Select-Object -ExpandProperty trigger -ErrorAction SilentlyContinue) {
        if (($_.ruleConditions | Where-Object { $_.trigger } | Select-Object -ExpandProperty trigger).access -eq $true) {
            $Trigger = "access"
        }
    }

    [PSCustomObject]@{
        RuleID            = $_._id
        RuleName          = $_.name
        Action            = $_.ruleAction.action
        Trigger           = $Trigger
        Enabled           = $_.enabled
        SimulationMode    = $_.simulationMode
        SourceUserNames   = $SourceUserNames
        SourceEndpointNames = $SourceEndpointNames
        DestinationNames  = $DestinationNames
        AccessTypes       = $AccessTypes
        TemplateId        = $_.templateId
        EmailNotificationEnabled = $_.emailNotification.enabled
        EmailNotificationSubject = $_.emailNotification.properties.subject
        IndicatorNotificationEnabled = $_.indicatorNotification.enabled
        IndicatorNotificationSeverity = $_.indicatorNotification.properties.severity
        CreatedAt         = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    }
}

# Output to console
Write-Host "`n--- [-] Identity Protection Policy Rules ---`n" -ForegroundColor Cyan
$FormattedRules | Format-Table -AutoSize

# Export to CSV
Write-Host "Exporting policy rules to $OutputCSV..."
try {
    $FormattedRules | Export-Csv -Path $OutputCSV -NoTypeInformation
    Write-Host "Policy rules exported to: $OutputCSV"
}
catch {
    Write-Error "Failed to export to CSV. Error: $_"
}

Write-Host "Done."
