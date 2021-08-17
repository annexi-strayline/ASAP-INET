# ASAP-INET
ANNEXI-STRAYLINE AURA Public (ASAP) Repository - INET subsystem for TCP/IP/UDP and TLS

This subsystem is a member of the larger [ASAP Repository](https://github.com/annexi-strayline/ASAP)

This subsystem provides general IP communication facilities, including TLS support.

Currently this subsystem supports the following:

* IPv4 and IPv6
* Host lookup
* TCP
* TLS (TCP)

TLS support is implemented through a binding to [LibreSSL's](https://libressl.org/) [libtls](https://man.openbsd.org/tls_init.3). The TLS implementation is a tagged type extension of the TCP protocol facilities, giving a highly abstracted TLS stream interface that requires minimum effort to configure and use.
