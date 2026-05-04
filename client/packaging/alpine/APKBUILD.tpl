# Contributor: Trieu Truong <quangtrieu1312@gmail.com>
# Maintainer: Trieu Truong <quangtrieu1312@gmail.com>
pkgname=masque
pkgver=%%PKGVER%%
pkgrel=%%PKGREL%%
pkgdesc="MASQUE VPN client (IP-over-HTTP3/QUIC, multi-client)"
url="https://github.com/quangtrieu1312/masque-vpn"
arch="x86_64"
license="MIT"
depends=""
makedepends=""
options="!check"  # pre-built binary requires NET_ADMIN at runtime
subpackages="$pkgname-openrc"
source="
	masque
	masque.conf.template
	masque.initd
"
builddir="$srcdir"

build() {
	:
}

package() {
	install -Dm755 "$builddir"/masque \
		"$pkgdir"/usr/bin/masque

	install -Dm644 "$builddir"/masque.conf.template \
		"$pkgdir"/etc/masque/masque.conf.template

	install -dm755 "$pkgdir"/etc/masque/certs
	install -dm750 "$pkgdir"/var/logs/masque

	# default_openrc() will automatically split this into the -openrc subpackage
	install -Dm755 "$builddir"/masque.initd \
		"$pkgdir"/etc/init.d/masque
}
