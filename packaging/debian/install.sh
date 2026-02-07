#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

deb_path="$(${script_dir}/build-deb.sh)"

echo "built: ${deb_path}" >&2
echo "installing with dpkg (needs sudo)" >&2

sudo dpkg -i "${deb_path}"

echo "" >&2
echo "installed." >&2
echo "edit: /etc/hosts-dns-forwarder/hosts-dns-forwarder.env" >&2
echo "then: systemctl restart hosts-dns-forwarder" >&2
