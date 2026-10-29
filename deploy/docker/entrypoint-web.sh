#!/bin/sh
# DFIR lab - the monitored web host: Apache2 + dfir-agent in one container.
#
# Apache2 starts in the background so requests to :80 generate real
# /var/log/apache2/access.log entries. The agent then runs as the foreground
# process, so `docker compose logs web` shows agent activity and SIGTERM
# reaches the agent directly.
#
# Lab only: runs as root; the fixture is inert text, not executable PHP.
set -eu

uploads=/var/www/html/uploads

# 0755 so Apache (www-data) can serve the fixture over :80; the agent reads
# it as root regardless.
install -d -m 0755 "$uploads"
if [ ! -f "$uploads/fixture.php" ]; then
  printf 'DFIR lab fixture - not executable PHP\n' > "$uploads/fixture.php"
fi

# Start Apache without systemd; logs go to /var/log/apache2/{access,error}.log.
apache2ctl start

exec /usr/local/bin/dfir-agent \
  -server http://dfir-server:8080 \
  -host-id lab-ubuntu \
  -uploads "$uploads" \
  -web-config /etc/apache2/apache2.conf \
  -web-logs /var/log/apache2/access.log,/var/log/apache2/error.log
