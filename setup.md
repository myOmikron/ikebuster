## Libreswan logging

See https://libreswan.org/wiki/Setting_up_system_for_debug_logging

```bash
mkdir -p /etc/systemd/journald.conf.d
cat <<EOF > /etc/systemd/journald.conf.d/local.conf
[Journal]
# Rate limits
RateLimitInterval=0
RateLimitBurst=0
EOF
systemctl daemon-reload
systemctl restart systemd-journald.service
```
