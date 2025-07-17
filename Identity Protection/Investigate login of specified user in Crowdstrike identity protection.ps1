<#====================================
Investigate logins of specified user using Crowdstrike identity protection API
By Adi Mahluf - 10root Cyber Security
Comments to adim@10root.com

This PowerShell script is designed for security analysts and incident responders who need quick visibility into user authentication activity within environments integrated with CrowdStrike Identity Protection.
Last update: 16.07.2025
Minimum API Permission required:
- Identity Protection Entities - Read
- Identity Protection GraphQL - Write
- Identity Protection Timeline - Read

Current script limitation: 
- This script uses the SamAccountName attribute to identify users. In environments with multiple domains, this may result in capturing activity from different users who share the same SamAccountName across domains
- We do not support Gov clouds.
CC BY-NC 4.0 License
====================================#>

# ======== Important! Configure your parameters: ======== #
$clientID = "############################" # Your CrowdStrike API ClientID
$clientSecret = "########################################" # Your CrowdStrike API client secret
$SamAccountName = "adim"          # User to investigate. Use plain SAMaccountname.
$Duration = "P-7D"                # # CASE-SENSITIVE! P-1M for Last 1 month, P-2W for Last 2 weeks, P-7D for 7 days, PT7H for 7 hours, PT30M for last 30 minutes, PT15S for last 15 seconds.
$Reportexportpath = "C:\10root\" #Report export directory. no need to specify file name. If not specify any value ($null) - CSV report will not be created.
$Cloud = "us-1" # Default is US-1. options are US-1, US-2, EU-1.



#################DO NOT MAKE CHANGE BELOW THIS LINE########################

# API URLs
if ($Cloud -like $null -or $Cloud -like "US-1") {
$TokenUrl = "https://api.crowdstrike.com/oauth2/token"
$GraphQLUrl = "https://api.crowdstrike.com/identity-protection/combined/graphql/v1"}

if ($Cloud -like "us-2") {
$TokenUrl = "https://api.us-2.crowdstrike.com/oauth2/token"
$GraphQLUrl = "https://api.us-2.crowdstrike.com/identity-protection/combined/graphql/v1"}

if ($Cloud -like "EU-1") {
$TokenUrl = "https://api.eu-1.crowdstrike.com/oauth2/token"
$GraphQLUrl = "https://api.eu-1.crowdstrike.com/identity-protection/combined/graphql/v1"}

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

# STEP 1: Validate SAM account exists in Identity Protection
Write-Host "Validating account: $SamAccountName..."

$EntityQuery = @"
{
  entities(first: 1 accountQuery: { samAccountNames: ["$SamAccountName"] }) {
    nodes {
      primaryDisplayName
      secondaryDisplayName
      accounts {
        ... on ActiveDirectoryAccountDescriptor {
          samAccountName
          domain
        }
      }
    }
  }
}
"@

$EntityBody = @{ query = $EntityQuery } | ConvertTo-Json -Depth 5
$EntityResponse = Invoke-RestMethod -Uri $GraphQLUrl -Method Post -Headers $Headers -Body $EntityBody

$Accounts = $EntityResponse.data.entities.nodes.accounts
if (-not $Accounts) {
    Write-Warning "No account found for SAM $SamAccountName. Check if user exists in Identity Protection."
    exit
}

Write-Host "Found account: $($Accounts[0].samAccountName)@$($Accounts[0].domain)"

# STEP 2: Query timeline for logons
Write-Host "Querying timeline for last $Duration..."

$TimelineQuery = @"
{
  timeline(
    types: [SUCCESSFUL_AUTHENTICATION]
    startTime: "$Duration"
    sourceEntityQuery: {
      accountQuery: { samAccountNames: ["$SamAccountName"] }
    }
    first: 100
    sortOrder: DESCENDING
  ) {
    nodes {
      timestamp
      eventType
      ... on TimelineAuthenticationEvent {
        endpointEntity {
          primaryDisplayName
        }
        ipAddress
        deviceType
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"@

$TimelineBody = @{ query = $TimelineQuery } | ConvertTo-Json -Depth 5
$TimelineResponse = Invoke-RestMethod -Uri $GraphQLUrl -Method Post -Headers $Headers -Body $TimelineBody

$Events = $TimelineResponse.data.timeline.nodes
if (-not $Events) {
    Write-Warning "No login events found for $SamAccountName in the last $Duration."
    exit
}

# Format results
$Results = $Events | ForEach-Object {
    [PSCustomObject]@{
        Timestamp = $_.timestamp
        Endpoint  = $_.endpointEntity.primaryDisplayName
        IP        = $_.ipAddress
        Device    = $_.deviceType
    }
}

# Output to screen
Write-Host "`n--- [-] Login and Ticket Renewal Events of $SamAccountName ---`n" -ForegroundColor Cyan

$Results | Format-Table -AutoSize

# Export to CSV
if ($Reportexportpath -notlike $null) {
$export = "$($Reportexportpath)$($SamAccountName).csv"
Write-Host "[-] Exporting report to $export" -ForegroundColor Cyan
$Results | Export-Csv -Path $export -NoTypeInformation
Write-Host "`nResults exported to: $export. Done."
}