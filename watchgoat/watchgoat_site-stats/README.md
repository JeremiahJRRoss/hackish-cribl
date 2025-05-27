WatchGoat Site Stats is designed to use Cribl Stream or Edge to monitor a website from global vantage points. Statistics are output as a single line of json. 
To run this app from Cribl Stream or Edge
 - Save the script to a directory on your linux host (e.g. /opt/watchgoat/)
 - Apply ownership to the cribl user (e.g. chown -R cribl:cribl /opt/watchgoat)
 - Create an exec source that runs the script every 60 seconds with 1 potential retry

**Example command**
/opt/watchgoat/watchgoat_site-stats.py --url https://cribl.io --port 443 --regex "Privacy Policy" --timeout 10

**Example output:**
{"dns_resolution_time":0.002,"dns_resolved_ip":"76.76.21.21","dns_server_ip":"127.0.0.53","tcp_connect_time":0.005,"tls_handshake_time":0.015,"tls_version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","http_status":200,"http_version":"1.1","content_length":649659,"time_to_first_byte":0.07,"content_download_time":0.027,"regex_match":true,"target_url":"https://cribl.io","source_hostname":"wg-aws-usw2-01","timeout_occurred":false,"message":"Success"}

**version notes***
001: The basic of the basic
 - Resolves DNS
 - Provides DNS resolution & server
 - Negotiates TLS
 - Makes a GET request
 - Evaluates regex
 - Returns results

as of this version nothing has been verfied except that it seems to work :)
