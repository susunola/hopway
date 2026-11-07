# sing-quic source in HopWay

Upstream module: `github.com/sagernet/sing-quic`
Version: `v0.7.2-0.20261020082049-7e0a5869a5f4`
Source: [SagerNet/sing-quic@7e0a586](https://github.com/SagerNet/sing-quic/tree/7e0a5869a5f4)

This local Go module contains the pinned upstream Go sources and module files.
The original copyright and license notice is in LICENSE.
The GNU GPL version 3 text is in COPYING.

HopWay tracks waiters on the shared Hysteria2 and TUIC connection offers.
The last canceled waiter cancels the pending offer and waits for cleanup.
Concurrent waiters and established transports keep their original lifetime.
