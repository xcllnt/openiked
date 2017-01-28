OpenIKED
========

This version of OpenIKED is derived from the openiked.org version,
which is itself a port of OpenBSD's iked to Darwin/OS X and other
operating systems.  This version has grown features and improvements
not found in the original version.

iked is a lean Internet Key Exchange (IKEv2) daemon which performs
mutual authentication and which establishes and maintains IPsec VPN
flows and security associations (SAs) between the two peers.  The
IKEv2 protocol is defined in RFC 5996, which combines and updates the
previous standards: ISAKMP/Oakley (RFC 2408), IKE (RFC 2409), and the
Internet DOI (RFC 2407).  iked only supports the IKEv2 protocol;
support for ISAKMP/Oakley and IKEv1 is provided by OpenBSD's
isakmpd(8) or other implementations on non-OpenBSD platforms.

iked supports mutual authentication using RSA public keys and X.509
certificates, it also support responder/server-side authentication of
clients using the EAP-MSCHAPv2 protocol over IKEv2.  It interconnects
with other IKEv2 implementations like the native IKEv2 implementation
of Windows 7 or newer (aka Agile VPN) or strongSwan.

* http://www.openbsd.org/cgi-bin/cvsweb/src/sbin/iked/
* http://www.openbsd.org/cgi-bin/cvsweb/src/usr.sbin/ikectl/
* See also: http://www.openiked.org/

Installation
------------

The portable version of OpenIKED uses the GNU autoconf environment to
build and install from the sources.  As usual, follow these basic
steps to install OpenIKED:

1. Requirements:
    - Make sure that the external libraries OpenSSL (version 1.0 or newer)
and libevent (version 1.4 or newer) with their header files are
installed.
    - If you're checking out the sources from the Git repository, you will
also need GNU automake, autoconf (version 2.69 or newer) and libtool.
2. Enter the top directory of the extracted sources.
3. If you checked out the sources from the Git repository, run
`sh bootstrap` to generate the required build files.
4. Run `./configure` in this directory to generate the Makefiles.
    - `./configure --help` will show you some available build options.
    - For example, you can run the following when building on Apple OS X
with MacPorts:
```
    ./configure --with-ssl-dir=/opt/local/ \
        --with-libevent-dir=/opt/local/lib/libevent1/ \
        --prefix=/opt/local/
```
5. Type `make` to build all parts of OpenIKED including iked and ikectl.
6. Type `make install` to install OpenIKED, or `sudo make install` if
you didn't compile OpenIKED as root.

7. Run something like the following to create iked's unprivileged
system user and environment. Note that the command syntax and user
name might vary on different platforms - use "iked" instead of "_iked"
on Linux.
```
	# mkdir /var/empty
	# chown root:sys /var/empty
	# chmod 755 /var/empty
	# groupadd _iked
	# useradd -g _iked -c 'iked privsep' -d /var/empty -s /sbin/nologin _iked
```

For creating system users on newer versions of Apple OS X, refer to
the `dscl` command line utility, eg.
```
	# dscl . -list /Groups gid | sort -n -k 2
	# dscl . -create /Groups/_iked gid 300
	# dscl . -create /Groups/_iked RealName "OpenIKED"
	# dscl . -create /Groups/_iked passwd "*"
	# dscl . -list /Users UniqueID | sort -n -k 2
	# dscl . -create /Users/_iked
	# dscl . -create /Users/_iked NFSHomeDirectory /var/empty
	# dscl . -create /Users/_iked uid 300
	# dscl . -create /Users/_iked gid 300
	# dscl . -create /Users/_iked UserShell /usr/bin/false
	# dscl . -create /Users/_iked RealName "OpenIKED"
	# dscl . -create /Users/_iked passwd "*"
```

8. On FreeBSD, NetBSD and maybe other BSD-variants IPsec is not
enabled in the default GENERIC kernel.  You have to compile a custom
kernel and enable options like `IPSEC`.  Please refer to the
individual documentation for details, for example:

* http://www.freebsd.org/doc/en_US.ISO8859-1/books/handbook/ipsec.html
* http://www.netbsd.org/docs/network/ipsec/#config_kernel

Development
-----------

The source tree of OpenIKED contains the following directories:

* `openiked/`:
    Build scripts for automake/autoconf and README files.
* `openiked/ikectl/`:
    The control and status utility for iked.
* `openiked/iked/`:
    The IKEv2 daemon itself and some files that are shared with ikectl.
* `openiked/openbsd-compat/`:
    Portability glue and API functions for non-OpenBSD platforms.

You can checkout this version from GitHub:

```
$ git clone git://github.com/xcllnt/openiked.git
```

Before you continue with looking at the code or writing any diffs, you
should study OpenBSD's source style guide; or the "KNF". You can
find it in OpenBSD's style(9) manpage or online at:
http://www.openbsd.org/cgi-bin/man.cgi?query=style&sektion=9.
Please also note that each line should be at most 80 characters long.

Authors
-------

* Marcel Moolenaar <marcel@brkt.com>
* Reyk Floeter <reyk@openbsd.org>
* Mike Belopuhov <mikeb@openbsd.org>

See [`LICENSE.md`](https://github.com/xcllnt/openiked/blob/master/LICENSE.md)
for information about copyright and licensing.

Caveats, bugs and limitations
-----------------------------

OpenIKED might have a few limitations on operating systems other than
the most recent versions of OpenBSD.  A major difference between
OpenBSD and other systems is the API and availability of the IPsec
PFKEYv2 flow implementation (SADB) and message passing between kernel
and iked.  Current known limitations are:

* VPN traffic leakage prevention:
Automatic blocking of IPv6 traffic is not working on KAME-bases stacks.

* Crypto algorithms:
Some of the crypto algorithms are either not supported on other systems
or not implemented correctly.  For example, Linux still uses the broken
pre-standard version of hmac-sha2-256 by default that was specified with
96 bit truncation instead of the standard 128 bit truncation.  The common
workaround that allows to specify the truncation length would be to use
Linux' non-standard XFRM kernel API instead of PFKEYv2.

Marcel

[![Flattr this git repo](http://api.flattr.com/button/flattr-badge-large.png)](https://flattr.com/thing/1038961/reykopeniked-on-GitHub)
