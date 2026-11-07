# cidr.nim

IPv4/IPv6 **CIDR notation** parsing and operations for Nim. Zero dependencies — builds on `std/net`'s `IpAddress`.

```nim
import cidr, std/net

let net = parseCidr("192.168.1.0/24")

echo net.contains(parseIpAddress("192.168.1.55"))   # true
echo parseIpAddress("192.168.2.1") in net           # false
echo net.lastAddress                                # 192.168.1.255
echo parseCidr("10.1.2.3/8").normalized             # 10.0.0.0/8
echo toPrefixLen(parseIpAddress("255.255.255.0"))   # 24
```

## Why?

`std/net` gives you `IpAddress`, but nothing for working with *networks*: no CIDR parsing, no containment checks, no overlap detection. Every firewall tool, log analyzer, IP allowlist and server dashboard ends up reinventing that. `cidr` fills the gap with a small, well-tested API.

## Features

- **Parse** IPv4 and IPv6 CIDR blocks (`10.0.0.0/8`, `2001:db8::/32`), bare addresses become host blocks (`/32`, `/128`)
- **Containment**: `net.contains(ip)` and `bigNet.contains(smallNet)`
- **Overlap** detection between blocks
- **Network / last address** (broadcast/top), host-bit normalization
- **Netmask conversion**: `255.255.255.0` → `/24` (rejects non-contiguous masks)
- **Block size** (`/24` → 256 addresses), saturating for huge IPv6 blocks
- **Subnet enumeration**: split a block into subnets (`iterSubnets` is lazy — safe for huge IPv6 ranges; `subnets` is eager with a safety cap)
- **Supernet / merge**: walk up to a parent block (`supernet`), or compute the smallest single block containing two blocks (`commonSupernet`)
- Self-contained **equality**: `parseCidr(a) == parseCidr(b)` works with a bare `import cidr`
- Zero dependencies, pure standard library, `CidrError` (a `ValueError`) on bad input

## Installation

```
nimble install cidr
```

or add to your `.nimble`:

```
requires "cidr >= 0.3.0"
```

## API quick reference

| Proc | Description |
|---|---|
| `parseCidr(s: string): Cidr` | Parse `a.b.c.d/len`, host bits normalized |
| `c.contains(ip: IpAddress): bool` | Address membership (`in` works too) |
| `outer.contains(inner: Cidr): bool` | Subnet containment |
| `overlaps(a, b: Cidr): bool` | Do the blocks share any address? |
| `c.networkAddress / c.lastAddress` | First / top address of the block |
| `c.normalized` | Canonical form with host bits cleared |
| `c.size: BiggestUInt` | Number of addresses (saturates at 2^64) |
| `toPrefixLen(netmask: IpAddress): int` | Netmask → prefix length |
| `c.iterSubnets(newPrefixLen): iterator` | Enumerate subnets, first to last. Lazy — safe for ranges that cannot even be counted in 64 bits; stop early when you have enough |
| `c.subnets(newPrefixLen, maxBlocks = 4096): seq[Cidr]` | Eager version with a safety cap; raises when the split exceeds it |
| `c.supernet(newPrefixLen): Cidr` | Parent block at a shorter prefix — the inverse of `subnets` |
| `commonSupernet(a, b: Cidr): Cidr` | Smallest single block containing both (the merge of two blocks) |

## Example: splitting a block into subnets

```nim
import cidr

for sub in parseCidr("192.168.1.0/24").subnets(26):
  echo sub
# 192.168.1.0/26
# 192.168.1.64/26
# 192.168.1.128/26
# 192.168.1.192/26

# Huge IPv6 splits: the lazy iterator returns on demand,
# no 2^120-counting required.
var first = 0
for sub in parseCidr("2001:db8::/32").iterSubnets(36):
  echo sub
  inc first
  if first == 4:
    break
```

## Example: merging blocks

```nim
import cidr

let merged = commonSupernet(parseCidr("192.168.1.0/24"),
                            parseCidr("192.168.2.0/24"))
echo merged                # 192.168.0.0/22 — smallest block covering both
echo merged.supernet(16)   # 192.168.0.0/16 — one level further up
```

## Example: private-network classifier

See [examples/private_net.nim](examples/private_net.nim):

```nim
import cidr, std/net

const PrivateNets = [parseCidr("10.0.0.0/8"), parseCidr("172.16.0.0/12"),
                     parseCidr("192.168.0.0/16")]

proc isPrivate(ip: IpAddress): bool =
  PrivateNets.anyIt(it.contains(ip))

echo isPrivate(parseIpAddress("192.168.0.1"))  # true
echo isPrivate(parseIpAddress("8.8.8.8"))      # false
```

## Running tests

```
nimble test
```

43 unit tests, CI on Nim 1.6 / 2.0 / 2.2 / stable.

## License

MIT
