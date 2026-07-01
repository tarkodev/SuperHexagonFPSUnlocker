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
