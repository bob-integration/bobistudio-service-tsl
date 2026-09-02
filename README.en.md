# TSL — the Bobi.Studio tally and label service

*[Version française](README.md)*

> ⚠ **Requires Bobi.Studio 0.9.2 or newer.** The tally model now lives in the core (`app.tally`),
> this service carrying only the protocol. On an older version that module does not exist: the
> service **will not start**, failing with an ImportError at load time.

A **TSL 5.0** implementation (tally and UMD) for [Bobi.Studio](https://github.com/bob-integration/bobistudio).
It takes tally from a broadcast controller, distributes it to multiviewer windows, and writes
source labels.

---

## The model, and why it does not mirror the frame

TSL 5.0 reserves two bits for each of its three fields — **LH**, **RH**, **TT**. A "step of
three" that comes from the **frame format**, not from any production reality.

This service does not inherit it. A **tally level** here is a named entity, identified by a
UUID that never moves — the number shown in the interface is only a rank, which reordering
rewrites freely. An installation declares as many as it wants — the code imposes no ceiling —
and can rename or reorder them without rewriting a single configuration.

A TSL connection feeds **one** level: its destination chain. Its three LH/RH/TT fields are not
three chains but three ways of expressing that one level's state — `rouge_field` and
`vert_field` say which ones carry red and green. A level has several states: `off`, `red`,
`green`, `amber`, amber being the two together.

**One connection, one TCP server.** Several controllers can feed the same installation without
colliding, each on its own port.

---

## The protocol on the wire

Offsets **verified by capture**, not read from a document:

```
SOM `FE 02` @0 · LEN (2, LE) @2 · VER/FLAGS @4 · SCREEN (2, LE) @6
INDEX (2, LE) @8 · CONTROL (2, LE) @10 · LENGTH (2, LE) @12 · TEXT @14 (Latin-1)
```

`INDEX` is the display index — the source. In `CONTROL`, bits 0-1 carry RH, 2-3 TT, 4-5 LH,
each valued `0=off`, `1=red`, `2=green`, `3=amber`.

⚠ **The index is at offset 8.** An earlier version of our own documentation put it at 4, and
everything fell back onto index 0 — a silent regression, every source showing the first one's
tally. If you are implementing TSL 5.0 yourself, that is the mistake not to repeat.

---

## Using it

This repository is a **service** of Bobi.Studio, mounted at `services/tsl/`. Configure it under
**Settings → Protocols → TSL**: connections, levels, label columns.

The distributor reads the configuration of deployed multiviewers and sends colour and text per
window. The `set_label` action is exposed to macros, to write a source label from a sequence.

It is not usable on its own: its connections and levels live in the orchestrator's database.

---

## Licence

GPL-3.0-or-later — see [LICENSE](LICENSE). Copyright © 2026 BOBI SAS, France.
