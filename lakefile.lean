import Lake
open System Lake DSL

package libsodiumLean where
  extraDepTargets := #[`libsodium_shim]
  moreLinkArgs := #[
    "-L/usr/local/lib",
    "-Wl,-rpath,/usr/local/lib",
    "-Wl,--allow-shlib-undefined",
    "-lsodium",
    "-lzlog"
  ]

@[default_target]
lean_lib LibsodiumLean

lean_lib Examples

target sodium_shim_o pkg : FilePath := do
  let srcFile := pkg.dir / "sodium" / "sodium_shim.c"
  let oFile := pkg.buildDir / "c" / "sodium_shim.o"
  IO.FS.createDirAll oFile.parent.get!
  let flags := #["-fPIC", "-O2", "-I", (← getLeanIncludeDir).toString, "-I/usr/local/include"]
  compileO oFile srcFile flags
  return .pure oFile

extern_lib libsodium_shim pkg := do
  let shimObj ← sodium_shim_o.fetch
  let name := nameToStaticLib "sodium_shim"
  buildStaticLib (pkg.staticLibDir / name) #[shimObj]

lean_exe examples where
  root := `Examples.Main

require zlogLean from git
  "git@github.com:marcellop71/zlog-lean.git" @ "main"

