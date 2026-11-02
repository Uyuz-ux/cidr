# Copyright 2026 Uyuz-ux
# Licensed under the MIT License.

# Classify an IP address as private (RFC 1918) using cidr.

import std/[net, sequtils]
import cidr

const PrivateNets = [
  parseCidr("10.0.0.0/8"),
  parseCidr("172.16.0.0/12"),
  parseCidr("192.168.0.0/16"),
]

proc isPrivate(ip: IpAddress): bool =
  PrivateNets.anyIt(it.contains(ip))

for candidate in ["192.168.0.1", "10.42.0.7", "172.20.1.1", "172.32.0.1",
                  "8.8.8.8", "2001:db8::1"]:
  let ip = parseIpAddress(candidate)
  echo candidate, " -> ", if ip.isPrivate: "private" else: "public"
