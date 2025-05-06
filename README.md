# DYRS
DYRS dynamic DNS IP checker &amp; companion

### Usage
Use with crontab or systemd to detect changes.

``` bash
*/5 * * * * /_path_to_dyrs_/ >> /var/log/ddns.log 2>&1
```

## WIP

Endpoints to external provider

Cloudflare, Namecheap support


## TOML Based Config

```toml
check_interval = 300
ip_source = "https://api.ipify.org"

[cloudflare]
enabled = true
api_token = "CF_API_TOKEN"
zone_id = "CF_ZONE_ID"
record_id = "CF_RECORD_ID"
record_name = "home.abc.dev"

```
