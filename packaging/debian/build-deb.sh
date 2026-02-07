#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

package_name="hosts-dns-forwarder"
maintainer="${DEB_MAINTAINER:-hosts-dns-forwarder <root@localhost>}"

version="$(awk -F '"' '/^[[:space:]]*version[[:space:]]*=[[:space:]]*"/ { print $2; exit }' "${repo_root}/Cargo.toml")"
if [[ -z "${version}" ]]; then
  echo "error: failed to detect version from Cargo.toml" >&2
  exit 1
fi

arch="$(dpkg --print-architecture)"
out_dir="${repo_root}/dist"
out_deb="${out_dir}/${package_name}_${version}_${arch}.deb"

tmp_root="$(mktemp -d)"
trap 'rm -rf "${tmp_root}"' EXIT

# Avoid packaging a 0700 top-level directory entry.
chmod 0755 "${tmp_root}"

echo "building ${package_name} ${version} (${arch})" >&2

(
  cd -- "${repo_root}"
  cargo build --release
)

bin_path="${repo_root}/target/release/hosts-dns-forwarder"
if [[ ! -x "${bin_path}" ]]; then
  echo "error: missing built binary: ${bin_path}" >&2
  exit 1
fi

mkdir -p "${tmp_root}/DEBIAN"

# Files
install -Dm0755 "${bin_path}" "${tmp_root}/usr/bin/hosts-dns-forwarder"
install -Dm0755 "${script_dir}/hosts-dns-forwarder-run" "${tmp_root}/usr/lib/hosts-dns-forwarder/hosts-dns-forwarder-run"
install -Dm0644 "${script_dir}/hosts-dns-forwarder.service" "${tmp_root}/lib/systemd/system/hosts-dns-forwarder.service"
install -Dm0644 "${script_dir}/hosts-dns-forwarder.env" "${tmp_root}/etc/hosts-dns-forwarder/hosts-dns-forwarder.env"

if [[ -f "${repo_root}/README.md" ]]; then
  install -Dm0644 "${repo_root}/README.md" "${tmp_root}/usr/share/doc/${package_name}/README.md"
fi

# Debian metadata
cat >"${tmp_root}/DEBIAN/control" <<EOF
Package: ${package_name}
Version: ${version}
Section: net
Priority: optional
Architecture: ${arch}
Maintainer: ${maintainer}
Depends: systemd
Description: Minimal DNS server honoring /etc/hosts, otherwise forwarding
 A tiny UDP DNS server written in Rust. It answers from /etc/hosts first and
 forwards everything else to upstream nameservers.
EOF

cat >"${tmp_root}/DEBIAN/conffiles" <<'EOF'
/etc/hosts-dns-forwarder/hosts-dns-forwarder.env
EOF

install -Dm0755 "${script_dir}/postinst" "${tmp_root}/DEBIAN/postinst"
install -Dm0755 "${script_dir}/prerm" "${tmp_root}/DEBIAN/prerm"
install -Dm0755 "${script_dir}/postrm" "${tmp_root}/DEBIAN/postrm"

mkdir -p "${out_dir}"
dpkg-deb --build --root-owner-group "${tmp_root}" "${out_deb}" >/dev/null

echo "${out_deb}"
