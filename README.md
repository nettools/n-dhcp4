# n-dhcp4 - Dynamic Host Configuration Protocol for IPv4

**ABOUT:**
        The n-dhcp4 project implements the IPv4 Dynamic Host Configuration
        Protocol as defined in RFC-2132+.

**DETAILS:**
        https://nettools.github.io/n-dhcp4

**BUG REPORTS:**
        https://github.com/nettools/n-dhcp4/issues

**GIT:**
        git@github.com:nettools/n-dhcp4.git
        https://github.com/nettools/n-dhcp4.git

**GITWEB:**
        https://github.com/nettools/n-dhcp4

**MAILINGLIST:**
        https://groups.google.com/forum/#!forum/nettools-devel

**LICENSE:**
        Apache Software License 2.0
        Lesser General Public License 2.1+
        See AUTHORS for details.

## Requirements:

The requirements for n-dhcp4 are:

```
  Linux kernel >= 3.19
  libc (e.g., glibc >= 2.16)
```

At build-time, the following software is required:

```
   meson >= 0.41
   pkg-config >= 0.29
```

## Install
        The meson build-system is used for this project. Contact upstream
        documentation for detailed help. In most situations the following
        commands are sufficient to build and install from source:

```
            $ mkdir build
            $ cd build
            $ meson setup ..
            $ ninja
            $ meson test
            # ninja install
```

        No custom configuration options are available.
