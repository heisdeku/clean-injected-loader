# clean-injected-loader

A safe, git-only tool to **detect and remove the "injected loader" malware** that
hides in JavaScript/TypeScript setup files and an accompanying `eval()`/C2 backdoor.
It can sweep a single repo, a whole folder of checkouts, an explicit list of repos,
or your entire GitHub account — and fix every branch without ever executing the
malicious code.

> **Safety first.** This tool uses **only git plumbing plus text tools**
> (`sed`/`grep`/`awk`). It **never** runs `npm`/`yarn`/`composer`, build/dev
> scripts, or migrations, so the backdoor is never executed. Do not run
> install/build on an unscanned checkout yourself.

---

## What it looks for

Two malware families, both surfaced as **IOCs** (indicators of compromise):

1. **Obfuscated createRequire loader** — scrambled code hidden in a setup file
   (`postcss.config.*`, `tailwind.config.*`, `next.config.*`, `commitlint.config.*`,
   `babel.config.*`, `.eslintrc.*`, WordPress `functions.php`, …) that rebuilds
   `require` to phone home. Marker: **`_$_`**. Usually paired with a tampered
   `.gitignore` that hides a dropped **`config.bat`**.
2. **`eval()` / C2 backdoor** — a config file that base64-decodes an API key, fetches
   a command-and-control URL, and `eval()`s the response. IOCs:
   `auth-confirm-eight.vercel.app`, `AUTH_API_KEY`, `"Auth Error!"`, an injected
   `node-fetch`, and a committed `.env`.

It also flags **`.env` hygiene** problems (a `.env` that isn't ignored, real secrets
committed to history) and surfaces any `eval(` for **manual review** (dual-use — not
auto-removed).

## How it fixes things

Per infected branch, **real work is always preserved** — only the tampered setup file
and the `.gitignore` `config.bat` line ever change:

1. restore the setup file to its **last clean version on that branch**, else
2. restore it from the **clean default branch**, else
3. **strip the injected loader in place** (when the file was infected from its first
   commit and no clean version exists anywhere).

`clean` adds one commit on top (no history rewrite). `purge` rewrites history so the
malware was never in the commits. All work happens in a throwaway worktree/clone, so
your real checkout is never touched.

---

## Install

```sh
git clone git@github.com:heisdeku/clean-injected-loader.git
cd clean-injected-loader
./install.sh          # symlinks the script onto your PATH at ~/bin/clean-injected-loader
```

Or just run it directly: `./clean-injected-loader.sh scan ~/dev`.

Requires: `bash`, `git`, and standard `sed`/`grep`/`awk`. The `--remote` mode also
needs the [GitHub CLI](https://cli.github.com) (`gh`) authenticated with `repo` scope.

---

## Usage

```
clean-injected-loader {scan|clean|purge|resync} [ROOT_DIR] [options]
```

| Command  | What it does                                                              |
|----------|---------------------------------------------------------------------------|
| `scan`   | Read-only report: IOCs, `eval()` review, `.env`/secret hygiene. Changes nothing. |
| `clean`  | Add a clean-up commit on top of each infected branch (safe, no history rewrite). |
| `purge`  | Rewrite history so the malware was never in the commits (**destructive**, force-push). |
| `resync` | Fast-forward stale local checkouts to the already-cleaned remote.         |

### Targets — pick where to operate

| Flag            | Operates on                                                                 |
|-----------------|------------------------------------------------------------------------------|
| `ROOT_DIR`      | Every git repo found under a local folder (default `.`).                      |
| `--list FILE`   | Exactly the repos listed in `FILE` (one per line; full git URL or `owner/name`; `#` comments + blank lines ok). Clones each into the workspace. No `gh` needed. |
| `--remote`      | Every repo on your `github.com/settings/repositories` (owned + collaborator + org), auto-enumerated via `gh`. |
| `--mine`        | Scope `--remote` to repos **you own**.                                        |
| `--owner=a,b`   | Scope `--remote` to the given owners only.                                    |

### Other options

| Flag              | Effect                                                                       |
|-------------------|------------------------------------------------------------------------------|
| `--push`          | `clean`: push the fix. `purge`: force-push the rewritten history.             |
| `--sign`/`--no-sign` | Force commit signing on/off (default **auto**: signs when `commit.gpgsign=true` + a signing key are configured, so commits show **Verified** on GitHub). |
| `--no-untrack`    | Keep committed `.env` files tracked (still restores ignore rules).            |
| `--no-env`        | Skip all `.env` handling (malware-only cleanup; `clean` only).                |
| `--no-resync`     | Don't touch local checkouts after pushing.                                    |
| `NOFETCH=1` (env) | Skip the network fetch on scans (use already-fetched refs).                   |

---

## The recommended workflow (list-based, transparent)

**1. Build a list** of the repos to check — one per line:

```
git@github.com:you/some-repo.git
you/another-repo
your-org/a-project
```

Generate it automatically with `gh`:

```sh
gh repo list YOUR-USERNAME --limit 300 --json sshUrl -q '.[].sshUrl' >  repos.txt
gh repo list YOUR-ORG      --limit 300 --json sshUrl -q '.[].sshUrl' >> repos.txt
```

**2. Preview** — looks only, changes nothing:

```sh
clean-injected-loader scan --list repos.txt
```

**3. Apply** — cleans every infected branch and pushes the fix:

```sh
clean-injected-loader clean --list repos.txt --push
```

**4. Refresh** your local checkouts to the cleaned remote:

```sh
clean-injected-loader resync ~/dev --fetch
```

Want to erase the malware from history entirely (not just add a fix on top)?
Use `purge --list repos.txt --push` — but collaborators must re-clone afterward,
and any leaked secret must still be **rotated**.

---

## Verified commits

The tool honors your git signing config so fix/purge commits show **Verified** on
GitHub. For SSH signing you need `commit.gpgsign=true`, `gpg.format=ssh`, and your
key set as `user.signingkey`. **The same key must also be registered on GitHub as a
Signing Key** (separate from an auth key) at `github.com/settings/keys`, or commits
show Unverified even when correctly signed.

`purge` re-signs every rewritten commit (a history rewrite invalidates old
signatures), so it is slower but comes out fully Verified.

---

## After a cleanup — don't skip

- **Rotate every secret** that may have been exposed (DB, JWT, API keys, cloud creds,
  GitHub tokens/SSH keys, payment gateways). History rewrites don't un-leak a secret.
- **Rotate GitHub access** and audit Deploy keys, authorized OAuth/GitHub Apps, and PATs.
- **Have collaborators scan their own machines** — if a teammate's machine is infected,
  it will re-push the loader into shared repos no matter what you rotate.
- **Enable branch protection** so direct force-pushes to `main`/`staging` are blocked.

---

## License

MIT — see [LICENSE](LICENSE).
