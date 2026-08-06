---
title: A stray "config/local copy" directory is partially tracked in git
slug: stray-config-local-copy-directory-tracked-in-git
---

Spotted while inventorying the repo, not investigated.

`config/local copy/` exists alongside `config/local/`. It contains what look like older versions of the real config files (`parental_profiles`, `parental_websites`, `parental_blocklists`, `crontab`, `tickets.html`, `README.md`, `.gitignore`).

Two things make it worth a look:

1. **Two of its files are tracked in git** (`config/local copy/.gitignore` and `config/local copy/README.md`), whereas the real `config/local/` is gitignored by design. The stray directory's own `.gitignore` uses the same `*` / `!.gitignore` / `!README.md` pattern, which is why exactly those two escaped.
2. It contains a `parental_websites` file, which no current script reads. `website-blocking.sh` reads `block_rules` and `parental_profiles` only, and `install.sh` never uploads a `parental_websites`. So the copy preserves a config format that has since been replaced.

Most likely an accidental duplicate from a file-manager copy, in which case deleting it is safe and removes a source of confusion about which config format is current. Not verified, and not deleted, because it may be a deliberate backup of a working configuration from before a format change.

Worth confirming with the repo owner before removing, since `config/local/` holds real household MAC addresses and credentials and is deliberately not in version control.
