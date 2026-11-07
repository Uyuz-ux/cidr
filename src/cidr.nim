# Copyright 2026 Uyuz-ux
# Licensed under the MIT License.

# Author: Uyuz-ux
# date  : 2026-11-03

## cidr — IPv4/IPv6 CIDR notation parsing and operations for Nim.
##
## Builds on `std/net`'s `IpAddress` and adds everything needed to work
## with networks in CIDR notation (`10.0.0.0/8`, `2001:db8::/32`):
## parsing, containment, overlap checks, network/last addresses,
## netmask conversion, subnet enumeration and supernet/merge
## operations. Zero dependencies beyond the standard library.
##
##   import cidr
##
##   let net = parseCidr("192.168.1.0/24")
##   echo net.contains(parseIpAddress("192.168.1.55"))  # true
##   echo net.contains(parseIpAddress("192.168.2.55"))  # false
##   echo net.lastAddress                               # 192.168.1.255
##   echo parseCidr("10.1.2.3/8").normalized            # 10.0.0.0/8
##   echo toPrefixLen(parseIpAddress("255.255.255.0"))  # 24
##   echo commonSupernet(parseCidr("192.168.1.0/24"),
##                       parseCidr("192.168.2.0/24"))   # 192.168.0.0/22

import std/[net, strutils]

type
  Cidr* = object
    ## A network in CIDR notation. `address` is always the normalized
    ## network address (host bits cleared).
    address*: IpAddress
    prefixLen*: int

  CidrError* = object of ValueError
    ## Raised when a string cannot be parsed as CIDR notation or a
    ## netmask is not contiguous.

proc cidrErr(msg: string): ref CidrError =
  new(result)
  result.msg = msg

func bitAt(ip: IpAddress, bitIndex: int): uint8 {.inline.} =
  ## Return bit `bitIndex` of `ip`, counting from the most significant
  ## bit of the whole address (bit 0 = MSB of the first byte).
  let byteIdx = bitIndex div 8
  let shift = 7 - (bitIndex mod 8)
  case ip.family
  of IPv4: (ip.address_v4[byteIdx] shr shift) and 1
  of IPv6: (ip.address_v6[byteIdx] shr shift) and 1

func withHostBits(address: IpAddress, prefixLen: int, hostBitValue: uint8): IpAddress =
  ## Copy `address` and set all host bits (everything after `prefixLen`)
  ## to `hostBitValue` (0 or 1).
  result = address
  let fullBytes = prefixLen div 8
  let remBits = prefixLen mod 8

  template clearTail(bytes: untyped) =
    var start = fullBytes
    if remBits > 0:
      inc start
    let tailFill = if hostBitValue != 0: 0xFF'u8 else: 0'u8
    for i in start ..< bytes.len:
      bytes[i] = tailFill
    if remBits > 0:
      let keepMask = uint8(0xFF'u8 shl (8 - remBits))
      let hostFill = if hostBitValue != 0: uint8(not keepMask) else: 0'u8
      bytes[fullBytes] = (bytes[fullBytes] and keepMask) or hostFill

  case address.family
  of IPv4: clearTail(result.address_v4)
  of IPv6: clearTail(result.address_v6)

func networkAddress*(c: Cidr): IpAddress =
  ## The first address of the network (already normalized).
  c.address

func lastAddress*(c: Cidr): IpAddress =
  ## The broadcast/top address of the network (all host bits set).
  withHostBits(c.address, c.prefixLen, 1)

func normalized*(c: Cidr): Cidr =
  ## Return the network with host bits cleared, e.g. `10.1.2.3/8`
  ## becomes `10.0.0.0/8`.
  Cidr(address: withHostBits(c.address, c.prefixLen, 0), prefixLen: c.prefixLen)

func prefixLenFromNetmaskBits(netmask: IpAddress): int =
  ## Count contiguous leading one-bits; -1 when the mask is not
  ## contiguous (e.g. 255.0.255.0).
  let totalBits = case netmask.family
    of IPv4: 32
    of IPv6: 128
  var ones = 0
  while ones < totalBits and netmask.bitAt(ones) == 1:
    inc ones
  for i in ones ..< totalBits:
    if netmask.bitAt(i) == 1:
      return -1
  return ones

func toPrefixLen*(netmask: IpAddress): int {.raises: [CidrError].} =
  ## Convert a dotted netmask (`255.255.255.0`) to a prefix length
  ## (`24`). Raises `CidrError` for non-contiguous masks.
  result = prefixLenFromNetmaskBits(netmask)
  if result < 0:
    raise cidrErr("netmask is not contiguous: " & $netmask)

proc parseCidr*(s: string): Cidr {.raises: [CidrError].} =
  ## Parse a CIDR block such as `10.0.0.0/8`, `192.168.1.7/24` or
  ## `2001:db8::/32`.
  ##
  ## * A plain address without `/` is treated as a single-host block
  ##   (`/32` for IPv4, `/128` for IPv6).
  ## * Host bits in the address part are allowed; the result is stored
  ##   normalized, so `$parseCidr("10.1.2.3/8") == "10.0.0.0/8"`.
  let parts = s.split('/')
  if parts.len > 2:
    raise cidrErr("too many '/': " & s)

  var address: IpAddress
  try:
    address = parseIpAddress(parts[0])
  except ValueError:
    raise cidrErr("invalid IP address: " & parts[0])

  var prefixLen: int
  case address.family
  of IPv4: prefixLen = 32
  of IPv6: prefixLen = 128

  if parts.len == 2:
    if parts[1].len == 0 or not parts[1].allCharsInSet({'0'..'9'}):
      raise cidrErr("invalid prefix length: " & parts[1])
    try:
      prefixLen = parseInt(parts[1])
    except ValueError:
      raise cidrErr("invalid prefix length: " & parts[1])
    let maxBits = case address.family
      of IPv4: 32
      of IPv6: 128
    if prefixLen < 0 or prefixLen > maxBits:
      raise cidrErr("prefix length out of range for IPv" &
        (if address.family == IPv4: "4" else: "6") & ": " & parts[1])

  result = Cidr(address: address, prefixLen: prefixLen).normalized

func `$`*(c: Cidr): string =
  ## Canonical string form: `address/prefixLen`.
  $c.address & "/" & $c.prefixLen

func `==`*(a, b: Cidr): bool {.inline.} =
  ## Two blocks are equal when address, prefix length and address family
  ## all match. Defined here so equality works with a bare `import cidr`
  ## (without pulling in `std/net`, whose `IpAddress` equality would
  ## otherwise be out of scope). Both operands are expected to be
  ## normalized - `parseCidr` results always are.
  runnableExamples:
    assert parseCidr("10.1.2.3/8") == parseCidr("10.0.0.0/8")
    assert parseCidr("10.0.0.0/8") != parseCidr("10.0.0.0/16")
  a.address == b.address and a.prefixLen == b.prefixLen

func contains*(c: Cidr, ip: IpAddress): bool =
  ## True when `ip` falls inside the network `c`. An IPv4 block never
  ## contains an IPv6 address and vice versa.
  if ip.family != c.address.family:
    return false
  for i in 0 ..< c.prefixLen:
    if c.address.bitAt(i) != ip.bitAt(i):
      return false
  return true

func contains*(outer, inner: Cidr): bool =
  ## True when `inner` is a subnet of (or equal to) `outer`.
  if outer.address.family != inner.address.family:
    return false
  if inner.prefixLen < outer.prefixLen:
    return false
  outer.contains(inner.address)

func overlaps*(a, b: Cidr): bool =
  ## True when the two networks share at least one address.
  if a.address.family != b.address.family:
    return false
  # Two CIDR blocks intersect iff one contains the other's network
  # address (blocks are power-of-two aligned ranges).
  a.contains(b.networkAddress) or b.contains(a.networkAddress)

func size*(c: Cidr): BiggestUInt =
  ## Number of addresses in the block. Blocks with 2^64 or more
  ## addresses (IPv6 /64 and shorter prefixes) saturate at
  ## `BiggestUInt.high`, since no integer type can hold 2^128.
  case c.address.family
  of IPv4:
    let hostBits = 32 - c.prefixLen
    if hostBits >= 32: 0xFFFFFFFF'u32.BiggestUInt
    else: (1'u64 shl hostBits).BiggestUInt
  of IPv6:
    let hostBits = 128 - c.prefixLen
    if hostBits >= 64: BiggestUInt.high
    else: 1'u64 shl hostBits

func prefixLenFromNetmaskStr*(s: string): int {.raises: [CidrError].} =
  ## Convenience wrapper: `toPrefixLen(parseIpAddress(s))`.
  var ip: IpAddress
  try:
    ip = parseIpAddress(s)
  except ValueError:
    raise cidrErr("invalid netmask: " & s)
  toPrefixLen(ip)

func setBitVal(ip: var IpAddress, bitIndex: int, value: uint8) {.inline.} =
  ## Write `value` (0 or 1) into bit `bitIndex` (MSB-first numbering,
  ## same convention as `bitAt`).
  let byteIdx = bitIndex div 8
  let mask = uint8(1'u8 shl (7 - (bitIndex mod 8)))
  case ip.family
  of IPv4:
    if value != 0: ip.address_v4[byteIdx] = ip.address_v4[byteIdx] or mask
    else: ip.address_v4[byteIdx] = ip.address_v4[byteIdx] and (not mask)
  of IPv6:
    if value != 0: ip.address_v6[byteIdx] = ip.address_v6[byteIdx] or mask
    else: ip.address_v6[byteIdx] = ip.address_v6[byteIdx] and (not mask)

func validateSubnetSplit(c: Cidr, newPrefixLen: int) {.raises: [CidrError].} =
  ## Shared argument validation for `iterSubnets` and `subnets`.
  let maxBits = case c.address.family
    of IPv4: 32
    of IPv6: 128
  if newPrefixLen < c.prefixLen:
    raise cidrErr("new prefix length (" & $newPrefixLen &
      ") is shorter than the block itself (" & $c.prefixLen & ")")
  if newPrefixLen > maxBits:
    raise cidrErr("prefix length out of range for IPv" &
      (if c.address.family == IPv4: "4" else: "6") & ": " & $newPrefixLen)

iterator iterSubnets*(c: Cidr, newPrefixLen: int): Cidr {.raises: [CidrError].} =
  ## Enumerates the subnets of `c` at `newPrefixLen`, first to last.
  ##
  ## The parent block is normalized first; every yielded subnet is
  ## contained in it and satisfies `parseCidr($subnet) == subnet`.
  ##
  ## The iterator is lazy and walks the subnet number by propagating a
  ## carry through the address bits, so it is safe for ranges that
  ## cannot be counted in a 64-bit integer (e.g. an IPv6 /0 split into
  ## /120s) - stop early with `break` or `toSeq(n)` as needed.
  ##
  ## Raises `CidrError` when `newPrefixLen` is shorter than the block's
  ## own prefix or out of range for the address family.
  runnableExamples:
    let block24 = parseCidr("192.168.1.0/24")
    for sub in block24.iterSubnets(26):
      echo sub    # 192.168.1.0/26, .64/26, .128/26, .192/26

  c.validateSubnetSplit(newPrefixLen)
  var cur = c.normalized.address
  while true:
    yield Cidr(address: cur, prefixLen: newPrefixLen)
    # Increment the subnet number: carry from the least significant
    # subnet bit (newPrefixLen-1) toward the most significant
    # (c.prefixLen). Wrap-around means every subnet was produced.
    var bit = newPrefixLen - 1
    var carried = true
    while carried and bit >= c.prefixLen:
      if cur.bitAt(bit) == 0:
        cur.setBitVal(bit, 1)
        carried = false
      else:
        cur.setBitVal(bit, 0)
        dec bit
    if carried:
      break

func subnets*(c: Cidr, newPrefixLen: int, maxBlocks = 4096): seq[Cidr] {.raises: [CidrError].} =
  ## Eager version of `iterSubnets`, capped for safety: raises
  ## `CidrError` when the split produces more than `maxBlocks` subnets
  ## (default 4096) or when the count does not fit in 64 bits. For
  ## unbounded ranges use the lazy `iterSubnets` instead.
  c.validateSubnetSplit(newPrefixLen)
  let delta = newPrefixLen - c.prefixLen
  if delta >= 64:
    raise cidrErr("split produces 2^" & $delta &
      " subnets, which does not fit a 64-bit count - use iterSubnets")
  let count = 1'u64 shl delta
  if count > maxBlocks.BiggestUInt:
    raise cidrErr("split produces " & $count & " subnets, above the " &
      $maxBlocks & " block cap - pass a larger maxBlocks or use iterSubnets")
  result = @[]
  for sub in c.iterSubnets(newPrefixLen):
    result.add(sub)

func supernet*(c: Cidr, newPrefixLen: int): Cidr {.raises: [CidrError].} =
  ## Parent block of `c` at `newPrefixLen` - the inverse of
  ## `iterSubnets`/`subnets`: every subnet of the result at
  ## `c.prefixLen` contains `c`. `newPrefixLen` must be shorter than or
  ## equal to the block's own prefix; anything else raises `CidrError`.
  runnableExamples:
    assert parseCidr("192.168.1.130/26").supernet(24) == parseCidr("192.168.1.0/24")
    assert parseCidr("2001:db8:1::/48").supernet(32) == parseCidr("2001:db8::/32")
    assert parseCidr("10.0.0.0/8").supernet(8) == parseCidr("10.0.0.0/8")

  let maxBits = case c.address.family
    of IPv4: 32
    of IPv6: 128
  if newPrefixLen < 0 or newPrefixLen > maxBits:
    raise cidrErr("prefix length out of range for IPv" &
      (if c.address.family == IPv4: "4" else: "6") & ": " & $newPrefixLen)
  if newPrefixLen > c.prefixLen:
    raise cidrErr("new prefix length (" & $newPrefixLen &
      ") is longer than the block itself (" & $c.prefixLen &
      ") - a supernet must be equal or shorter")
  Cidr(address: withHostBits(c.address, newPrefixLen, 0), prefixLen: newPrefixLen)

func cmpAddr(x, y: IpAddress): int {.inline.} =
  ## Lexicographic byte comparison of two same-family addresses
  ## (-1, 0 or 1). Behavior is unspecified when families differ.
  case x.family
  of IPv4:
    for i in 0 ..< 4:
      if x.address_v4[i] != y.address_v4[i]:
        return if x.address_v4[i] < y.address_v4[i]: -1 else: 1
  of IPv6:
    for i in 0 ..< 16:
      if x.address_v6[i] != y.address_v6[i]:
        return if x.address_v6[i] < y.address_v6[i]: -1 else: 1
  0

func commonSupernet*(a, b: Cidr): Cidr {.raises: [CidrError].} =
  ## Smallest single CIDR block that contains both `a` and `b` (the
  ## "merge" of two blocks). Raises `CidrError` when the blocks belong
  ## to different address families.
  runnableExamples:
    assert commonSupernet(parseCidr("192.168.1.0/24"),
                          parseCidr("192.168.2.0/24")) == parseCidr("192.168.0.0/22")
    assert commonSupernet(parseCidr("10.0.0.0/9"),
                          parseCidr("10.128.0.0/9")) == parseCidr("10.0.0.0/8")

  if a.address.family != b.address.family:
    raise cidrErr("cannot merge IPv4 and IPv6 blocks")
  let a = a.normalized
  let b = b.normalized
  let aLast = a.lastAddress
  let bLast = b.lastAddress
  # The union range is [lo, hi]; the smallest CIDR containing a
  # contiguous range has a prefix as long as the common bit prefix of
  # its endpoints.
  var lo, hi: IpAddress
  lo = if cmpAddr(a.address, b.address) <= 0: a.address else: b.address
  hi = if cmpAddr(aLast, bLast) >= 0: aLast else: bLast
  let totalBits = case a.address.family
    of IPv4: 32
    of IPv6: 128
  var l = 0
  while l < totalBits and lo.bitAt(l) == hi.bitAt(l):
    inc l
  Cidr(address: withHostBits(lo, l, 0), prefixLen: l)
