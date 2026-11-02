version       = "0.1.0"
author        = "Uyuz-ux"
description   = "IPv4/IPv6 CIDR notation parsing and operations for Nim. Zero dependencies."
license       = "MIT"
srcDir        = "src"

# Deps

requires "nim >= 1.6.0"

task test, "Run the test suite":
  exec "nim c -r --hints:off --path:src -o:nimcache/tcidr tests/tcidr.nim"
