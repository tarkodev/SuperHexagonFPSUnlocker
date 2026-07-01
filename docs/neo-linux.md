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

Runtime diagnostics are not implemented for this patcher yet.
