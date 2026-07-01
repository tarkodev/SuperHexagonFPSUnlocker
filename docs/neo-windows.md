# Neo Windows Patcher

The Neo Windows patcher targets the Neo Windows Steam build:

```text
File: SuperHexagon.exe
SHA-256: 72b0c26053c37edd3435def461e9027cd6ffad12032db2fd0b32c256fdbee6b9
Size: 1467904 bytes
```

It keeps simulation timing at the original cadence, raises render pacing, and
interpolates selected visual fields during draw. Existing legacy patch states
from earlier experiments are detected so users can migrate cleanly.

Default menu choices:

```text
90, 120, 144, 165, 240, 360
```

The Neo Windows patcher accepts any whole FPS value above `60` from the command
line or the menu's custom option. `60 FPS` is handled by restoring the original
executable. Very high modes are experimental and depend on the display, driver,
and system pacing.

## Swap-Aware Pacing

The current Neo Windows patch also hooks the game's swap/present wrapper. The
hook does not disable VSync or force a driver setting. It only records that a
swap happened.

On the next timer delta, if a swap was observed, the patch clamps the render
accumulator to at most one render interval before the game decides whether to
draw again. This keeps a blocked swap/present from building up a render backlog
and then emitting immediate catch-up draws. In frame-by-frame recordings, that
backlog can show up as irregular duplicate frames even when the average FPS
looks correct.

The internal render pacer still controls VSync-off behavior. With VSync on, the
display mode, GPU driver, fullscreen/windowed mode, Windows compositor, and
capture tools can still affect presentation timing, but the patch avoids adding
extra catch-up jitter on top of those systems.

Older Neo Windows patches that do not include this swap-aware pacing are
detected as `legacy-no-swap-pacing`. Running the patch command again migrates
them to the current layout.

For testing, use the diagnostic command and compare update, draw, and swap
rates:

```text
uv run superhexagon-fps-unlocker diagnose --fps 240 --seconds 5 --warmup 2
```

The simulation update rate should stay near `60/s`, while draw and swap should
track the selected target when the platform is actually presenting that fast.
