n-dhcp4
=======

Dynamic Host Configuration Protocol for IPv4

The n-dhcp4 project implements the IPv4 Dynamic Host Configuration Protocol as
defined in RFC-2132+.

### Project

 * **Website**: <https://nettools.github.io/n-dhcp4>
 * **Bug Tracker**: <https://github.com/nettools/n-dhcp4/issues>
 * **Mailing-List**: <https://groups.google.com/forum/#!forum/nettools-devel>

### Requirements

The requirements for this project are:

 * `Linux kernel >= 3.19`
 * `libc` (e.g., `glibc >= 2.16`)
 * `glib-2.0` (if you build the check-dhcp4 tool)

At build-time, the following software is required:

 * `meson >= 0.41`
 * `pkg-config >= 0.29`

### Build

The meson build-system is used for this project. Contact upstream
documentation for detailed help. In most situations the following
commands are sufficient to build and install from source:

```sh
mkdir build
cd build
meson setup ..
ninja
meson test
ninja install
```

### Build check_dhcp

With the meson option -Dcheck_dhcp=true, check_dhcp binary is built around
the n-dhcp4 library, this binary broadcase a DHCP DISCOVER message
and listen for OFFER answer. His primary usage is for some kind of ping to
a DHCP server to know if it is currently responsive.

### Repository:

 - **web**:   <https://github.com/nettools/n-dhcp4>
 - **https**: `https://github.com/nettools/n-dhcp4.git`
 - **ssh**:   `git@github.com:nettools/n-dhcp4.git`

### License:

 - **Apache-2.0** OR **LGPL-2.1-or-later**
 - See AUTHORS file for details.
