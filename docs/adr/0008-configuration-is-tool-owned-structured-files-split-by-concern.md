# Configuration is tool-owned structured files, split by concern

**Status:** accepted

Configuration moves from pipe-delimited flat files to a structured format the tool reads and writes losslessly (JSON, since the tool has a decoder and the router needs no `jq`), split into separate files by concern: the device registry, profiles, schedules, and block rules. The tool is the authoritative writer. This is what makes a schedule editable from a phone: a UI that saves a schedule must not have to rewrite the device registry to do it, and it must not destroy anything a human put in the file.

## Considered Options

- **Tool-owned structured files, split by concern (chosen).** Round-trips losslessly, expresses a schedule window with a day-of-week set without inventing a delimiter convention, and limits the blast radius of any write to the concern being edited.
- **Keep pipe-delimited flat files (rejected).** They cannot express a window with a day selector without nesting delimiters, and the tool rewriting them would destroy the hand-written comments that currently carry every device's name, which `docs/adr/0003-devices-are-named-and-profiles-group-them.md` already identifies as the reason names have to become data.
- **UCI (rejected, but not obviously).** It is the OpenWrt-native format, `uci` works on it from the shell, and LuCI could read it. Rejected because the tool would gain a dependency on a config system it does not otherwise need, and because nothing else in this system is expressed through UCI. Recorded because it is the option a future reader will reasonably ask about, and because `docs/architecture.md` lists "pipe-delimited rather than UCI" as a choice made with no recorded rationale, so this ADR supersedes that non-decision with an actual one.
- **One file for everything (rejected).** Simple, and it is what exists today, but it forces every write to touch every concern and it is what `docs/adr/0003` is already splitting apart.

## Consequences

- This lands the config-schema half of ADR 0003: the device registry becomes its own file, device names become data rather than comments, and a device can be registered without belonging to a profile.
- Schedules become data the tool can render and edit, which is the precondition for both a status page saying "blocked until 08:00" and for schedules being windows with day selectors rather than cron edges.
- A migration from the current flat files is required, and it must preserve the device names that today exist only as comments, since those are the thing being promoted to data.
- Hand-editing remains possible and is not a supported round-trip: the tool may reformat. Anything a human must be able to keep should be a real field rather than a comment.
- The pull and push story of ADR 0007 acts on these files, and AdGuard's own YAML sits alongside them rather than being converted, since AdGuard owns that format.
