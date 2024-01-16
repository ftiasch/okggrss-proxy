#!/bin/bash
set -o errexit
cd "$(dirname "${BASH_SOURCE[0]}")"
. ../.env/bin/activate
if [[ "$1" == "down" ]]; then
	python cli.py down
fi
python cli.py gen
sing-box check -c run/config.json
sudo cp run/config.json /etc/sing-box/custom.json
sudo systemctl restart sing-box@custom
