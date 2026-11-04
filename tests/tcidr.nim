# Copyright 2026 Uyuz-ux
# Licensed under the MIT License.

import std/[unittest, net, sequtils]
import cidr

suite "parseCidr":
  test "basic IPv4 parsing":
    let c = parseCidr("192.168.1.0/24")
    check($c == "192.168.1.0/24")
    check(c.prefixLen == 24)

  test "host bits are normalized":
    check($parseCidr("10.1.2.3/8") == "10.0.0.0/8")
    check($parseCidr("192.168.1.77/24") == "192.168.1.0/24")

  test "bare address becomes host block":
    check($parseCidr("1.2.3.4") == "1.2.3.4/32")
    check($parseCidr("::1") == "::1/128")

  test "IPv6 parsing":
    let c = parseCidr("2001:db8::/32")
    check($c == "2001:db8::/32")
    check(c.prefixLen == 32)
    check($parseCidr("2001:db8::1/64") == "2001:db8::/64")

  test "rejects garbage":
    expect CidrError: discard parseCidr("not-an-ip/24")
    expect CidrError: discard parseCidr("1.2.3.4/-1")
    expect CidrError: discard parseCidr("1.2.3.4/33")
    expect CidrError: discard parseCidr("1.2.3.4/abc")
    expect CidrError: discard parseCidr("1.2.3.4/24/8")
    expect CidrError: discard parseCidr("::1/129")
    expect CidrError: discard parseCidr("1.2.3.4/")

suite "contains":
  test "IPv4 membership":
    let c = parseCidr("192.168.1.0/24")
    check(c.contains(parseIpAddress("192.168.1.0")))
    check(c.contains(parseIpAddress("192.168.1.255")))
    check(c.contains(parseIpAddress("192.168.1.55")))
    check(not c.contains(parseIpAddress("192.168.2.55")))
    check(not c.contains(parseIpAddress("192.167.1.55")))

  test "zero prefix contains everything (IPv4)":
    let c = parseCidr("0.0.0.0/0")
    check(c.contains(parseIpAddress("8.8.8.8")))
    check(c.contains(parseIpAddress("192.168.1.1")))

  test "IPv6 membership":
    let c = parseCidr("2001:db8::/32")
    check(c.contains(parseIpAddress("2001:db8::1")))
    check(c.contains(parseIpAddress("2001:db8:ffff::ff")))
    check(not c.contains(parseIpAddress("2001:db9::1")))

  test "version mismatch is never contained":
    let v4 = parseCidr("0.0.0.0/0")
    check(not v4.contains(parseIpAddress("::1")))

  test "operator sugar":
    let c = parseCidr("10.0.0.0/8")
    check(parseIpAddress("10.20.30.40") in c)

suite "subnet and overlap":
  test "subnet containment":
    let big = parseCidr("10.0.0.0/8")
    let small = parseCidr("10.1.0.0/16")
    check(big.contains(small))
    check(not small.contains(big))
    check(parseCidr("10.1.0.0/16").contains(parseCidr("10.1.2.0/24")))

  test "equal blocks contain each other":
    let a = parseCidr("10.0.0.0/8")
    check(a.contains(parseCidr("10.0.0.0/8")))

  test "non-overlapping detection":
    check(not parseCidr("10.0.0.0/8").contains(parseCidr("11.0.0.0/8")))

  test "overlap checks":
    check(overlaps(parseCidr("10.0.0.0/8"), parseCidr("10.1.0.0/16")))
    check(overlaps(parseCidr("10.1.0.0/16"), parseCidr("10.0.0.0/8")))
    check(overlaps(parseCidr("10.0.0.0/24"), parseCidr("10.0.0.16/28")))
    check(not overlaps(parseCidr("10.0.0.0/24"), parseCidr("10.0.1.0/24")))
    check(not overlaps(parseCidr("10.0.0.0/24"), parseCidr("2001:db8::/32")))

suite "addresses and size":
  test "network and last address":
    let c = parseCidr("192.168.1.130/25")
    check($c.networkAddress == "192.168.1.128")
    check($c.lastAddress == "192.168.1.255")

  test "last address for /32 and /128":
    check($parseCidr("1.2.3.4/32").lastAddress == "1.2.3.4")
    check($parseCidr("2001:db8::1/128").lastAddress == "2001:db8::1")

  test "size":
    check(parseCidr("10.0.0.0/8").size == 16777216'u)
    check(parseCidr("192.168.1.0/24").size == 256'u)
    check(parseCidr("1.2.3.4/32").size == 1'u)
    check(parseCidr("2001:db8::/64").size == BiggestUInt.high)  # 2^64 saturates
    check(parseCidr("2001:db8::/65").size == 9223372036854775808'u)
    check(parseCidr("2001:db8::/20").size == BiggestUInt.high)

suite "netmask conversion":
  test "dotted netmasks":
    check(toPrefixLen(parseIpAddress("255.255.255.0")) == 24)
    check(toPrefixLen(parseIpAddress("255.0.0.0")) == 8)
    check(toPrefixLen(parseIpAddress("255.255.255.252")) == 30)
    check(toPrefixLen(parseIpAddress("0.0.0.0")) == 0)
    check(toPrefixLen(parseIpAddress("255.255.255.255")) == 32)

  test "non-contiguous netmask raises":
    expect CidrError:
      discard toPrefixLen(parseIpAddress("255.0.255.0"))

  test "string wrapper":
    check(prefixLenFromNetmaskStr("255.255.0.0") == 16)
    expect CidrError:
      discard prefixLenFromNetmaskStr("999.999.999.999")

suite "real world usage":
  test "private network classification":
    let privates = [parseCidr("10.0.0.0/8"), parseCidr("172.16.0.0/12"),
                    parseCidr("192.168.0.0/16")]
    proc isPrivate(ip: string): bool =
      privates.anyIt(it.contains(parseIpAddress(ip)))
    check(isPrivate("10.1.2.3"))
    check(isPrivate("172.31.255.255"))
    check(isPrivate("192.168.0.1"))
    check(not isPrivate("172.32.0.1"))
    check(not isPrivate("8.8.8.8"))

suite "subnets":
  test "split /24 into /26s":
    let parts = parseCidr("192.168.1.0/24").subnets(26)
    check(parts.len == 4)
    check($parts[0] == "192.168.1.0/26")
    check($parts[1] == "192.168.1.64/26")
    check($parts[2] == "192.168.1.128/26")
    check($parts[3] == "192.168.1.192/26")

  test "block count is 2^(delta)":
    check(parseCidr("10.0.0.0/16").subnets(24).len == 256)
    check(parseCidr("10.0.0.0/16").subnets(20).len == 16)

  test "first and last subnet boundaries":
    let parts = parseCidr("10.1.0.0/16").subnets(20)
    check($parts[0] == "10.1.0.0/20")
    check($parts[^1] == "10.1.240.0/20")

  test "every subnet is contained in the parent and parses to itself":
    let parent = parseCidr("172.16.0.0/16")
    for sub in parent.subnets(19):
      check(parent.contains(sub))
      check(parseCidr($sub) == sub)

  test "equal prefix yields the single normalized block":
    let parts = parseCidr("10.1.2.3/24").subnets(24)
    check(parts.len == 1)
    check($parts[0] == "10.1.2.0/24")

  test "invalid prefix lengths raise":
    expect CidrError:
      discard parseCidr("10.0.0.0/24").subnets(16)
    expect CidrError:
      discard parseCidr("10.0.0.0/24").subnets(33)
    expect CidrError:
      discard parseCidr("2001:db8::/32").subnets(129)

  test "IPv6 split /124 into /126s":
    let parts = parseCidr("2001:db8::/124").subnets(126)
    check(parts.len == 4)
    check($parts[0] == "2001:db8::/126")
    check($parts[^1] == "2001:db8::c/126")

  test "iterator is lazy: huge IPv6 range can be abandoned early":
    # /0 -> /120 is 2^120 blocks; taking two must return immediately.
    var got: seq[Cidr] = @[]
    for sub in parseCidr("::/0").iterSubnets(120):
      got.add(sub)
      if got.len == 2:
        break
    check(got.len == 2)
    check($got[0] == "::/120")
    check($got[1] == "::100/120")

  test "eager cap raises and can be raised explicitly":
    expect CidrError:
      discard parseCidr("0.0.0.0/0").subnets(24)
    expect CidrError:
      discard parseCidr("10.0.0.0/16").subnets(24, maxBlocks = 128)
    check(parseCidr("10.0.0.0/16").subnets(24, maxBlocks = 300).len == 256)
