# CLI Reference

`imhotep` follows the shared QYVORA tier grammar:

```
imhotep <tier> <module> [<action>] [target] [flags]
```

`<tier>` is one of `recon`, `exploit`, or `report`. Every pre-tier command remains available as a hidden alias.

## recon

_No recon-tier modules._

## exploit

_No exploit-tier modules._

## report

_No report-tier modules._

## Utilities

| Command | Purpose |
|---------|---------|
| `imhotep assess` | run the analysis pipeline against a snapshot or simulation |
| `imhotep evidence` | inspect the latest assessment evidence |
| `imhotep findings` | inspect the latest assessment findings |
| `imhotep providers` | list supported cloud providers and their status |
| `imhotep rules` | list the registered analysis rules |
| `imhotep snapshot` | generate a deterministic sample cloud snapshot |
| `imhotep target` | manage assessment targets (snapshot files and simulation) |
| `imhotep tui` | start the interactive terminal application |
| `docs script <file>` | Run a `.qs` script with the shared scripting engine (`run`/`build` subcommands) |
