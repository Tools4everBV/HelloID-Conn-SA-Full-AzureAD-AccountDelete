# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#Change mapping here
$account = [PSCustomObject]@{
    userPrincipalName = $userPrincipalName;
}

try{
    Hid-Write-Status -Message "Generating Microsoft Graph API Access Token.." -Event Information

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }
 
    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    Hid-Write-Status -Message "Deleting AzureAD user [$($account.userPrincipalName)].." -Event Information
 
    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }
 
    $baseUpdateUri = "https://graph.microsoft.com/"
    $updateUri = $baseUpdateUri + "v1.0/users/$($account.userPrincipalName)"
    $body = $account | ConvertTo-Json -Depth 10
 
    $response = Invoke-RestMethod -Uri $updateUri -Method DELETE -Headers $authorization -Body $body -Verbose:$false

    Hid-Write-Status -Message "AzureAD user [$($account.userPrincipalName)] deleted successfully" -Event Success
    HID-Write-Summary -Message "AzureAD user [$($account.userPrincipalName)] deleted successfully" -Event Success
}catch{
    HID-Write-Status -Message "Error deleting AzureAD user [$($account.userPrincipalName)]. Error: $_" -Event Error
    HID-Write-Summary -Message "Error deleting AzureAD user [$($account.userPrincipalName)]" -Event Failed
}
