# Neo Linux Patcher

The Neo Linux patcher targets the Neo Linux Steam build:

```text
File: SuperHexagon
SHA-256: 6f13c58d136b84df212cc23a560f7383e2f689005af18072e51d8a7439d2ba1d
Size: 2253968 bytes
```

It patches the known x86-64 build by byte signatures and refuses unknown layouts
unless `--force` is supplied.

The patch keeps simulation timing at the original 60 FPS cadence and raises
native render pacing to the selected target. The Linux patcher leaves the
game's draw-time visual state untouched; the Neo Windows interpolation path is
not enabled here until the Linux-only object layout is fully validated.

Default menu choices:

```text
90, 120, 144, 165, 240, 360
```

Custom values can be any whole FPS value above `60`. `60 FPS` is handled by
restoring the original executable.

Unlike the Neo Windows patcher, this patcher does not add a new executable
section. It reuses part of the original `setGameFrameRate` code area as patch
space, so restoring a patched Linux executable requires the original `.bak`
backup. The patcher preserves Unix executable permissions when writing both the
patched file and the restored file.

## How It Works

The Linux binary is an ELF64 executable with a fixed image base. The patcher
keeps the file size unchanged and edits known byte signatures in place:

- `superhex::setGameFrameRate(int)` is replaced with the patch cave.
- `superhex::update()` jumps into a fixed-60 simulation gate.
- `ofSetFrameRate(int)` is hooked so native window pacing uses the selected FPS.
- The window constructor timer setup is patched so the initial frame interval
  also uses the selected FPS.
- `expectedFrameDelta` is kept at `1.0`, matching normal 60 FPS simulation.

The patch cave stores immutable constants inside the reused
`setGameFrameRate` code area. Runtime values that change every frame, such as
the update accumulator and previous rotation snapshot, are stored in writable
`.data` padding near `expectedFrameDelta`; writing those values into `.text`
crashes on Linux because the executable code mapping is not writable.

`superhex::update()` still receives a 60 FPS simulation delta. The hook reads
`ofGetLastFrameTime()`, accumulates real elapsed render time, and only enters
the original update body when at least one 60 FPS step is due. If not enough
time has elapsed, the hook returns early and the next render can happen without
advancing gameplay.

`superhex::draw()` is intentionally left untouched. A direct port of the Neo
Windows draw interpolation is not currently safe on Linux because the 64-bit
object layout is not a byte-for-byte match with the 32-bit Windows layout; some
fields also live in a nested `gameclass` subobject. The earlier experimental
Linux draw hook caused visible corruption, so the supported Linux patch keeps
draw-time visual state original until each Linux offset is independently
validated.

Old Neo Linux patches from this project are detected as
`legacy-timing-scaling`. Those patches raised the game's frame-rate fields and
scaled frame delta instead of running a fixed 60 FPS simulation gate. When a
valid `.bak` original exists, patching over that legacy state migrates by
rebuilding the executable from the original backup and applying the current
patch.

Runtime diagnostics are not implemented for this patcher yet.
