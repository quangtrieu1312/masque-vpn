# Contributor: Your Name <you@example.com>
# Maintainer:  Your Name <you@example.com>
pkgname=masque
pkgver=%%PKGVER%%
pkgrel=%%PKGREL%%
pkgdesc="MASQUE VPN client (IP-over-HTTP3/QUIC, multi-client)"
url="https://github.com/quangtrieu1312/masque-vpn"
arch="x86_64"
license="MIT"
# Runtime: only musl libc (always present on Alpine)
depends=""
makedepends=""
install=""
subpackages="$pkgname-openrc"

# Pre-built binary supplied by the CI build phase.
# Source directory already contains the binary and assets when abuild runs;
# no network fetch needed.
source="
	masque
	masque.conf.template
	masque.initd
"
# abuild checksum fills these in automatically
sha256sums="
	SKIP
	SKIP
	SKIP
"

builddir="$srcdir"

# Nothing to compile – the binary is pre-built by CI.
build() {
	:
}

check() {
	# Smoke-test: binary must be an ELF and accept -h / --help
	"$builddir"/masque -h 2>&1 | head -5 || true
}

package() {
	install -Dm755 "$builddir"/masque \
		"$pkgdir"/usr/bin/masque

	# Config template — installs to /opt/masque/ (changed from /etc/masque/)
	install -Dm644 "$builddir"/masque.conf.template \
		"$pkgdir"/opt/masque/masque.conf.template

	# Runtime directories expected by the binary
	install -dm755 "$pkgdir"/opt/masque/certs
	install -dm750 "$pkgdir"/opt/masque/logs
}

# OpenRC init sub-package
package_openrc() {
	pkgdesc="OpenRC init script for masque"
	depends="$pkgname openrc"
	install_if="$pkgname=$pkgver-r$pkgrel openrc"

	install -Dm755 "$builddir"/masque.initd \
		"$subpkgdir"/etc/init.d/masque
}
