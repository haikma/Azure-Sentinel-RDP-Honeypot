
$API_KEY = "<a46ddca631d246c3a6c51b72729bcca8>" 

$LOGFILE_NAME = "failed_rdp.log"
$LOGFILE_PATH = "C:\ProgramData\$LOGFILE_NAME"

# Tạo file log nếu chưa tồn tại
if (!(Test-Path $LOGFILE_PATH)) {
    New-Item -Path $LOGFILE_PATH -ItemType File
    Write-Host "Created log file at: $LOGFILE_PATH" -ForegroundColor Green
}

Write-Host "Starting Failed Login Monitor..." -ForegroundColor Cyan

# Vòng lặp vô hạn để quét log liên tục
while ($true) {
    try {
        # Lấy các sự kiện Event ID 4625 (Logon Failure) mới nhất
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddSeconds(-2)} -ErrorAction SilentlyContinue

        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $ipAddress = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "IpAddress"} | Select-Object -ExpandProperty "#text"

            if ($ipAddress -and $ipAddress -ne "-") {
                
                # Gọi API để lấy thông tin địa lý
                $url = "https://api.ipgeolocation.io/ipgeo?apiKey=$API_KEY&ip=$ipAddress"
                $response = Invoke-RestMethod -Uri $url -Method Get -ErrorAction SilentlyContinue

                if ($response) {
                    # Lấy dữ liệu cần thiết
                    $timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    $country = $response.country_name
                    $latitude = $response.latitude
                    $longitude = $response.longitude
                    $state = $response.state_prov
                    
                    # Định dạng dòng log tùy chỉnh
                    $log_entry = "$timestamp, ip:$ipAddress; country:$country; state:$state; latitude:$latitude; longitude:$longitude; label:Honeypot-Attack;"
                    
                    # Ghi vào file
                    Add-Content -Path $LOGFILE_PATH -Value $log_entry
                }
            }
        }
    }
    catch {
        # Bỏ qua lỗi
    }
    Start-Sleep -Seconds 1
}