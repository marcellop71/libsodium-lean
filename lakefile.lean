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

/-- Compile `src` into `oFile` with a build trace over `src` and `deps` (local headers,
    `#include`d `.c` files), so editing any of them rebuilds the object and the archives
    that use it. `weakArgs` (include paths) are kept out of the trace. -/
def tracedO (oFile src : FilePath) (deps : Array FilePath := #[])
    (weakArgs traceArgs : Array String := #[]) : SpawnM (Job FilePath) := do
  let inputs ← (#[src] ++ deps).mapM inputTextFile
  let srcJob ← (Job.collectArray inputs).mapM fun _ => pure src
  buildO oFile srcJob weakArgs traceArgs

target sodium_shim_o pkg : FilePath := do
  tracedO (pkg.buildDir / "c" / "sodium_shim.o") (pkg.dir / "sodium" / "sodium_shim.c")
    (weakArgs := #["-I", (← getLeanIncludeDir).toString, "-I/usr/local/include"])
    (traceArgs := #["-fPIC", "-O2"])

extern_lib libsodium_shim pkg := do
  let shimObj ← sodium_shim_o.fetch
  let name := nameToStaticLib "sodium_shim"
  buildStaticLib (pkg.staticLibDir / name) #[shimObj]

lean_exe examples where
  root := `Examples.Main

require zlogLean from git
  "git@github.com:marcellop71/zlog-lean.git" @ "v4.35.0"

