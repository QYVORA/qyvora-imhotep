# Imhotep

> **Offline cloud snapshot analysis framework.**
> A terminal-first console and CLI for cloud security assessment: IAM,
> storage, network, container and secret exposure plus misconfigurations —
> from recorded snapshots, with no live provider access.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

Imhotep is QYVORA's cloud security assessment framework for **offline
cloud snapshots** and deterministic simulations. It runs as a shared
terminal-first console **and** a one-shot CLI with identical commands, and
produces evidence-backed findings with transparent risk scoring. **Live
provider collection is not implemented and is refused honestly**; secret
material is redacted at collection time.

- **One workflow, two surfaces** — the console commands equal the CLI
  commands.
- **Deterministic `--sim`** — fixed dataset exercises every rule, no
  provider account required, CI-ready.
- **Offline only** — reads only the snapshots you explicitly provide;
  provider APIs are never contacted.
- **Redaction first** — secret values are redacted and never stored or
  printed.
- **Status** — shipped at v0.1.0 (Go 1.26+, MIT).

## Installation

```sh
git clone https://github.com/QYVORA/qyvora-imhotep.git
cd qyvora-imhotep
make build
sudo make install          # /usr/local layout (root)
make install-user          # ~/.local layout (no root)
```

Or build the single static binary directly with the Go toolchain:

```sh
go build ./cmd/imhotep
```

No release assets are published yet; `imhotep updates` installs release
builds once the first verifiable release exists.

## Quickstart

Full assessment, no input required, deterministic:

```sh
imhotep assess --sim       # risk 100/100 (critical)
```

Generate a sample cloud snapshot and assess it:

```sh
imhotep snapshot --sim
imhotep assess snapshot.sim.json
```

Interactive console (REPL on a real terminal; stdin piping uses a plain line reader):

```sh
imhotep
assess --sim
findings
evidence
exit
```

Machine-readable output:

```sh
imhotep capabilities -o json
imhotep assess -o json
imhotep report -o json
```

## Commands

```
assess        run the analysis pipeline against a snapshot or simulation
capabilities  print the machine-readable capability contract
console       start the interactive assessment console
evidence      inspect the latest assessment evidence
findings      inspect the latest assessment findings
providers     list supported cloud providers and their status
report        render the latest assessment report from disk
rules         list the registered analysis rules
snapshot      generate a deterministic sample cloud snapshot
target        manage assessment targets (snapshot files and simulation)
updates       check for and install verified releases
version       print version and build metadata
```

Global flags: `-o/--output`, `-q/--quiet`, `--no-color`.

## Analysis rules

```
IAM-001  Wildcard action granted                             high
IAM-002  Wildcard resource scope                             high
STG-001  Publicly readable storage                           high
STG-002  Publicly writable storage                        critical
STG-003  Unencrypted storage at rest                        medium
NET-001  Administrative port exposed to the internet         high
NET-002  Publicly accessible database                     critical
NET-003  Publicly exposed compute workload                   high
DBE-001  Unencrypted database at rest                       medium
CNT-001  Privileged container capability                     high
CNT-002  Host network namespace                             medium
CNT-003  Immutability-breaking image tag                      low
CNT-004  Container runs as root                             medium
SEC-001  Hardcoded secret material                         critical
```

## Capabilities

`imhotep capabilities` prints the machine-readable contract. The
deliberate boundary: `cloud.live` (live provider API collection) is
disabled — **snapshot-driven analysis only; provider SDKs are not wired
up**.

## Documentation

- **[`docs/README.md`](docs/README.md) — the documentation index.** It lists what is
  actually written, and names every zero-byte placeholder file explicitly so
  nothing empty is cited as documentation.
- Pipeline stages, analysis rules and risk scoring: the tool's own
  `capabilities` output, `docs/README.md`, and the QYVORA product overview.
- Cross-project contracts: the QYVORA tool output spec and ecosystem doc.

> **Documentation gap.** This repository still has zero-byte placeholder
> files (including `LICENSE` and `NOTICE`). `docs/README.md` names them all.

## Support

See [SUPPORT.md](SUPPORT.md). Report issues on GitHub.

## Contact

QYVORA OffSec — Tamale, Ghana
Website: https://qyvora.org · Security/Support: qyvorasec@gmail.com

## License

[MIT](LICENSE)

**Authorized use only.** Analyze cloud snapshots you are authorized to
evaluate; provider APIs are never contacted and secret values are never
stored or printed.