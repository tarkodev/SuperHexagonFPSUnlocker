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

Choose to patch at `90 FPS`, `120 FPS`, `144 FPS`, `165 FPS`, `240 FPS`,
`360 FPS`, or a custom FPS value!

## Commands

```text
uv run superhexagon-fps-unlocker status
uv run superhexagon-fps-unlocker restore
uv run superhexagon-fps-unlocker patch --fps 480
```

## Notes

For the smoothest result, disable in-game VSync and use the highest FPS value
that runs reliably on your setup. Some refresh rates, especially `144 Hz`, may
still show uneven frame pacing with consecutive new frames and occasional
duplicate frames. Thanks to [Stoic Sirius](https://steamcommunity.com/app/221640/discussions/0/3191363817373295516/#c567038823751565778)
for the frame-pacing report.

Close the game before patching or restoring.

When you patch the game, a `.bak` backup is created or refreshed next to the executable.

Supported Steam builds are Neo Windows, Neo Linux, and Pre-Neo Windows.

## Docs

- [Usage](docs/usage.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Neo Windows patcher](docs/neo-windows.md)
- [Neo Linux patcher](docs/neo-linux.md)
- [Pre-Neo Windows patcher](docs/pre-neo-windows.md)
