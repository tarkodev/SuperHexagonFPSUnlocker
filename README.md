# SuperHexagonFPSUnlocker

I love Super Hexagon. It was the first rhythm game I really got into, back when I was playing on my first Windows 7 PC, and I remember spending entire nights completely hooked on it.

Recently, I wanted to play it again and was surprised to see that the PC version was still capped at 60 FPS, even though I now use a 240 Hz monitor. The Android and iOS versions can already run at up to 120 FPS, so I wanted to see if the desktop version could be pushed further too.

After a lot of testing, and with some help from Codex using GPT-5.5, I managed to patch the executable and unlock higher refresh rates without any graphical issues. I also tried patching the old Pre-Neo version, but it was too unstable to really recommend. I left the code in the project for reference, but this project focuses on the Neo version, which is the current default version shipped on Steam.

The Linux port ended up being pretty straightforward thanks to the info in the [Super Hexagon Neo post](https://superhexagon.com/neo/): since Neo, the desktop versions share the same system-level code across Windows, Linux, and macOS, so the Windows and Linux builds behaved close enough for the patching work to carry over nicely.

I then made a simple Python script to make the patch easy to apply on both Windows and the Steam Deck OLED!

## Usage

Install Python 3.10+ and `uv`, then run from this folder:

```text
uv run superhexagon-fps-unlocker
```

On Neo Windows, choose to patch at `90 FPS`, `120 FPS`, `144 FPS`, `165 FPS`,
`240 FPS`, `360 FPS`, or a custom FPS value. Neo Linux and Pre-Neo Windows keep
the older `120 FPS`, `240 FPS`, `360 FPS`, and `480 FPS` choices.

## Commands

```text
uv run superhexagon-fps-unlocker status
uv run superhexagon-fps-unlocker restore
uv run superhexagon-fps-unlocker patch --fps 144
```

Neo Windows custom FPS values can be any whole number above `60`. Neo Linux and
Pre-Neo Windows custom FPS values must still be multiples of `60` and at least
`120`.

## Notes

For the cleanest pacing, choose a target FPS that is an integer multiple of your
display refresh rate, such as `288 FPS` or `432 FPS` on a `144 Hz` display. If
you see stutter or duplicate frames, disable in-game VSync and avoid targets
that do not divide evenly into your refresh rate.

Close the game before patching or restoring.

When you patch the game, a `.bak` backup is created or refreshed next to the executable.

Supported Steam builds are Neo Windows, Neo Linux, and Pre-Neo Windows.

## Docs

- [Usage](docs/usage.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Neo Windows patcher](docs/neo-windows.md)
- [Neo Linux patcher](docs/neo-linux.md)
- [Pre-Neo Windows patcher](docs/pre-neo-windows.md)
