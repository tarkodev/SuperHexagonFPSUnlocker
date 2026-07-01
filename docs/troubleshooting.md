# Troubleshooting

## The game says 240 IPS but still feels like 60 FPS

Run the diagnostic command:

```text
uv run superhexagon-fps-unlocker diagnose --fps 240
```

A healthy 240 FPS result should be close to:

```text
update: 60/s
draw:   240/s
swap:   240/s
```

If update is near 60/s but draw or swap is near 60/s, something outside the simulation loop is still limiting presentation.

Check these first:

- Make sure Windows is set to the monitor's high refresh mode.
- Disable in-game VSync.
- Check the GPU driver control panel for forced VSync, frame caps, or half-refresh modes.
- Try borderless/windowed vs fullscreen if your setup forces different presentation behavior.
- Close overlays or capture tools that may force a lower present rate.

## Duplicate frames on 144 Hz or similar displays

Use the Neo Windows patcher with a target FPS that is an integer multiple of the
display refresh rate. For example, try `288` or `432` on a `144 Hz` display.
Avoid mismatched targets such as `240` or `360` on `144 Hz`, and disable
in-game VSync if presentation pacing is uneven.

## The game runs too fast

That usually means an older speedup patch is still installed or the executable was patched by another tool.

Run:

```text
uv run superhexagon-fps-unlocker status
```

Then apply the current patch again:

```text
uv run superhexagon-fps-unlocker patch --fps 240
```

The current patch keeps the simulation cadence at the original rate. Only render
pacing and draw-time interpolation are changed.

## The patcher says the executable is unsupported

This patcher is signature-based and targets known Steam builds. If Steam updates the game or the file was modified, the SHA-256 hash can change.

Recommended recovery:

1. In Steam, verify the integrity of the game files.
2. Run `uv run superhexagon-fps-unlocker status`.
3. If the file is still unsupported, open an issue with the executable size, SHA-256, and command output.

Use `--force` only if you have confirmed the executable is layout-compatible with one of the supported builds.

## I want to remove the patch

Use:

```text
uv run superhexagon-fps-unlocker restore
```

Or restore the file through Steam's integrity check.
