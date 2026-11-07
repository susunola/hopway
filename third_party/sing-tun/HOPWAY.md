# sing-tun source in HopWay

Upstream module: `github.com/sagernet/sing-tun`
Version: `v0.9.7-0.20261023115432-040db71fcd33`
Source: [SagerNet/sing-tun@040db71](https://github.com/SagerNet/sing-tun/tree/040db71fcd33)

The local module includes the pinned Go sources and build assets. See LICENSE
for the original copyright and license notice and COPYING for the GPLv3 text.

HopWay can attach a shared byte budget and a drop callback to the UDP NAT
queue. The stack reserves before allocating and returns capacity on read,
discard, expiration, eviction and close. An upstream failure can also count
the unread packets it discards. Without a budget and callback, applications
keep the original queue behavior.

The UDP NAT connection exposes its underlying writer so callers can reserve
packet header space before reading a reply.
