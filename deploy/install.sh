#!/bin/zsh
# Installs the gateway and its tunnel as launchd agents. Usage: deploy/install.sh <public-hostname>
# Safe to run again. Needs a tunnel from: cloudflared tunnel create aside-mcp
set -euo pipefail
host=${1:?usage: install.sh <public-hostname>}
root=${0:A:h:h}
agents=$HOME/Library/LaunchAgents
logs=$HOME/Library/Logs/aside-mcp
config=$HOME/.config/aside-mcp
bun=$(command -v bun)
cloudflared=$(command -v cloudflared)
tunnel=$(cloudflared tunnel list --name aside-mcp --output json | jq -er '.[0].id')
mkdir -p "$logs" "$config" "$agents"
chmod 700 "$config"

cat > "$config/cloudflared.yml" <<YAML
tunnel: $tunnel
credentials-file: $HOME/.cloudflared/$tunnel.json
ingress:
  - hostname: $host
    service: http://127.0.0.1:7680
  - service: http_status:404
YAML

agent() { # label, then program arguments, one per line on stdin
  local label=$1 args=""
  while IFS= read -r line; do args+="    <string>$line</string>\n"; done
  print -r -- "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\"><dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key><array>
$(print -n -- "$args")
  </array>
  <key>WorkingDirectory</key><string>$root</string>
  <key>EnvironmentVariables</key><dict>
    <key>ASIDE_MCP_PUBLIC_URL</key><string>https://$host</string>
    <key>PATH</key><string>$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>$logs/$label.log</string>
  <key>StandardErrorPath</key><string>$logs/$label.log</string>
</dict></plist>" > "$agents/$label.plist"
  launchctl bootout "gui/$UID/$label" 2>/dev/null || true
  launchctl bootstrap "gui/$UID" "$agents/$label.plist"
}

agent me.justn.aside-mcp <<ARGS
$bun
src/server.ts
ARGS
agent me.justn.aside-mcp-tunnel <<ARGS
$cloudflared
tunnel
--no-autoupdate
--config
$config/cloudflared.yml
run
ARGS
echo "Installed. Connector URL: https://$host/mcp"
