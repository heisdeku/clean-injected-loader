#!/usr/bin/env bash
#
# clean-injected-loader.sh
# ------------------------
# Detect and remove the "injected loader" malware described in the cleanup
# walkthrough: scrambled code hidden in a setup file (postcss.config.*,
# tailwind.config.*, next.config.*, commitlint.config.*, WordPress
# functions.php) that uses a createRequire() helper to phone home, alongside a
# tampered .gitignore that hides a dropped `config.bat`.
#
# SAFETY: This script uses ONLY git plumbing plus text tools (sed/grep/awk).
# It NEVER runs npm/composer/build/dev, so the malicious code is never
# executed. Do not run install/build on an unscanned copy yourself.
#
# Usage:
#   clean-injected-loader scan  [ROOT_DIR]            # read-only report (default .)
#   clean-injected-loader clean [ROOT_DIR] [--push]   # fix infected branches
#
#   Add --remote to ANY command to operate on EVERY repo on your
#   github.com/settings/repositories page (owned + collaborator + org) instead
#   of local checkouts. It clones each via `gh` into the workspace, then runs
#   the same logic. Needs the `gh` CLI authenticated with `repo` scope.
#   e.g.  clean-injected-loader scan  --remote
#         clean-injected-loader clean --remote --push
#
# Fixing strategy, per infected branch (real work always preserved — only the
# tampered setup file + the .gitignore config.bat line ever change):
#   1. restore the setup file to its last clean version on that branch, else
#   2. restore it from the clean default branch (origin/HEAD), else
#   3. strip the injected loader out of the file in place (when it was infected
#      from its very first commit and no clean version exists anywhere).
# Each fix is one commit added on top (no history rewrite). Work happens in a
# throwaway git worktree off the existing repo, so it needs no re-clone and
# leaves your real working tree untouched.

set -uo pipefail

MARKER='_\$_'                 # git-grep (regex) form of the obfuscated-loader marker
MARKER_PLAIN='_$_'            # literal form for fixed-string grep on files
GITIGNORE_BAD='config.bat'    # dropped-file name hidden in .gitignore
WORKSPACE="${TMPDIR:-/tmp}/injected-loader-fix"
FIXED_MAP=()                  # filled per repo: "tmpbranch:originalbranch"

# Content IOCs from incident INC-2026-06-17-001 (Ekode/core-server backdoor) plus
# the obfuscated-loader campaign. ANY match in a tracked file = compromised.
# Used with `git grep -E`. See: drizzle.config.ts eval() C2 backdoor.
#   _$_                          obfuscated createRequire loader marker
#   auth-confirm-eight…vercel    command-and-control domain (incident IOC)
#   AUTH_API_KEY                 backdoor env var holding the base64 C2 key
#   Auth Error!                  the backdoor's benign-looking error label
C2_DOMAIN='auth-confirm-eight.vercel.app'
IOC_RE='_\$_|auth-confirm-eight\.vercel\.app|AUTH_API_KEY|Auth Error!'

# Commands that EXECUTE these backdoors — never run them on an unscanned checkout:
#   npm/yarn install, build/dev, AND (from the incident) drizzle-kit migrate,
#   db:migrate, db:generate, start:prod.

c_red() { printf '\033[31m%s\033[0m' "$1"; }
c_grn() { printf '\033[32m%s\033[0m' "$1"; }
c_yel() { printf '\033[33m%s\033[0m' "$1"; }
hr()    { printf '%s\n' "------------------------------------------------------------"; }

# Fail loudly on a bad ROOT_DIR instead of silently scanning nothing and
# reporting "clean". Echoes the absolute path on success.
require_dir() {
  if [ ! -d "$1" ]; then
    echo "$(c_red 'error'): root '$1' is not a directory." >&2
    echo "       give an existing path, e.g.  clean-injected-loader scan ~/dev" >&2
    exit 2
  fi
  ( cd "$1" && pwd )
}

# Load the SSH key this repo's origin uses into the agent, so the passphrase is
# entered ONCE instead of on every fetch/clone/push. No-op for https remotes,
# when the key is already loaded, or when ssh-agent isn't available.
ensure_key_loaded() {
  local url="$1" host key fp
  host="$(printf '%s' "$url" | sed -nE 's/^[a-zA-Z]+@([^:]+):.*/\1/p')"
  [ -z "$host" ] && return 0
  key="$(ssh -G "git@$host" 2>/dev/null | awk '/^identityfile /{print $2; exit}')"
  [ -z "$key" ] && return 0
  key="$(eval printf '%s' "$key")"          # expand a leading ~
  [ -f "$key" ] || return 0
  fp="$(ssh-keygen -lf "$key" 2>/dev/null | awk '{print $2}')"
  [ -n "$fp" ] && ssh-add -l 2>/dev/null | grep -q "$fp" && return 0   # already loaded
  echo "  loading SSH key (enter passphrase once): $key"
  ssh-add "$key" 2>/dev/null || true
}

# Is commit signing configured globally? (commit.gpgsign=true AND a signing key.)
# When yes, cleanup/purge commits are SIGNED so GitHub shows them "Verified";
# when no, we fall back to unsigned so the tool still works on a machine without
# a signing key. SIGN_COMMITS is set once per run from this, honoring --sign/--no-sign.
signing_configured() {
  [ "$(git config --get commit.gpgsign 2>/dev/null)" = "true" ] \
    && [ -n "$(git config --get user.signingkey 2>/dev/null)" ]
}

# Find every git repo under a root (depth-limited).
find_repos() {
  find "$1" -maxdepth 4 -type d -name .git 2>/dev/null | sed 's#/\.git$##' | sort -u
}

# ---------------------------------------------------------------------------
# REMOTE  (operate on the WHOLE GitHub account, not just local checkouts)
# ---------------------------------------------------------------------------
# `--remote` enumerates every repository shown on
# https://github.com/settings/repositories — everything the authenticated user
# owns, collaborates on, or reaches through an org — clones each into a local
# workspace, and then runs the normal scan/clean/purge logic against them. This
# catches infected repos that aren't checked out under ~/dev at all.
# Requires the GitHub CLI (`gh`), authenticated with at least `repo` scope.
REMOTE_ROOT="$WORKSPACE/remote"
OWNER_FILTER=""               # set by --owner=a,b or --mine to scope the sweep
LIST_FILE=""                  # set by --list FILE to clone an explicit repo list

# Emit "owner/name" for every repo on the settings/repositories page. The REST
# default affiliation is owner,collaborator,organization_member — exactly that
# page — but we pass it explicitly so the set never drifts. When OWNER_FILTER is
# set (comma-separated owners), keep only repos under those owners — a 206-repo
# account needs scoping, and it stops clean --push from touching repos you only
# collaborate on.
list_account_repos() {
  gh api --paginate \
    "user/repos?per_page=100&affiliation=owner,collaborator,organization_member" \
    --jq '.[].full_name' 2>/dev/null \
  | if [ -n "$OWNER_FILTER" ]; then grep -iE "^(${OWNER_FILTER//,/|})/"; else cat; fi
}

# Clone (or fetch-update) a STREAM of repo specs read from stdin into the given
# target dir, echoing that dir on stdout (progress goes to stderr so command
# substitution captures only the path). Each line may be a full git URL (ssh or
# https) or an "owner/name" shorthand; blank lines and # comments are ignored.
# $1 is a SET-SPECIFIC subdir so --remote and --list (and different list files)
# never scan each other's clones. Re-running the same set reuses + fetch-updates
# its clones. Uses ensure_key_loaded so the SSH passphrase is entered once.
clone_specs() {
  local target="$1"
  mkdir -p "$target"
  ensure_key_loaded "git@github.com:_/_.git"   # one passphrase up front, then silent
  local spec url name dir total=0 cloned=0 failed=0
  while IFS= read -r spec; do
    spec="${spec%%#*}"                   # strip trailing comment
    spec="${spec//[[:space:]]/}"         # strip all whitespace
    [ -z "$spec" ] && continue
    case "$spec" in
      *://*|*@*:*) url="$spec" ;;                       # full URL (ssh/https)
      */*)         url="git@github.com:${spec}.git" ;;  # owner/name shorthand
      *) echo "  $(c_yel 'skip') unrecognized repo: $spec" >&2; continue ;;
    esac
    name="$(printf '%s' "$url" | sed -E 's#\.git$##' | awk -F'[/:]' '{print $(NF-1)"__"$NF}')"
    dir="$target/$name"
    total=$((total+1))
    if [ -d "$dir/.git" ]; then
      [ "${NOFETCH:-0}" = 1 ] || git -C "$dir" fetch --quiet --all --prune 2>/dev/null
    else
      echo "  cloning $url" >&2
      if git clone --quiet "$url" "$dir" 2>/dev/null; then
        cloned=$((cloned+1))
      else
        echo "  $(c_red 'clone failed'): $url (check access / SSH key)" >&2
        failed=$((failed+1))
      fi
    fi
  done
  echo "  $total repos ($cloned freshly cloned, $failed failed) under $target" >&2
  echo "$target"
}

# --remote: enumerate the whole account via gh, then clone into REMOTE_ROOT/account.
sync_account_repos() {
  command -v gh >/dev/null 2>&1 || {
    echo "$(c_red 'error'): the GitHub CLI 'gh' is required for --remote." >&2
    echo "       install it (brew install gh), then run 'gh auth login'." >&2
    echo "       (or use --list repos.txt, which needs no gh)" >&2
    exit 2; }
  gh auth status >/dev/null 2>&1 || {
    echo "$(c_red 'error'): gh is not authenticated. Run 'gh auth login'." >&2
    exit 2; }
  echo "  enumerating account repositories via gh…" >&2
  list_account_repos | clone_specs "$REMOTE_ROOT/account"
}

# --list FILE: clone exactly the repos named in a user-provided file into a dir
# keyed to that file (so two different lists don't mix). Transparent (you control
# the list), needs no gh, works for repos under any host.
sync_repo_list() {
  local file="$1"
  [ -f "$file" ] || {
    echo "$(c_red 'error'): repo list '$file' not found." >&2
    echo "       make a file with one repo per line, e.g.:" >&2
    echo "         git@github.com:you/some-repo.git" >&2
    echo "         you/another-repo" >&2
    exit 2; }
  echo "  reading repos from $file" >&2
  local abs key; abs="$(cd "$(dirname "$file")" && pwd)/$(basename "$file")"
  key="$(printf '%s' "$abs" | cksum | cut -d' ' -f1)"
  clone_specs "$REMOTE_ROOT/list-$key" < "$file"
}

# Shared by every command: resolve the root. --list FILE and --remote both clone
# into REMOTE_ROOT and use that as the root; otherwise validate the given
# ROOT_DIR. For the cloned modes the clones are throwaway, so local-checkout
# resync is pointless — disable it; the caller hints to resync ~/dev separately.
resolve_root() {
  local remote="$1" root="$2"
  if [ -n "${LIST_FILE:-}" ]; then
    RESYNC=0
    sync_repo_list "$LIST_FILE"
  elif [ "$remote" = 1 ]; then
    RESYNC=0
    sync_account_repos
  else
    require_dir "$root"
  fi
}

# Remote branches of the repo in CWD, EXCLUDING the symbolic origin/HEAD pointer
# (whose short name is a bare remote like "origin" and must not be treated as a
# branch).
remote_branches() {
  git for-each-ref --format='%(refname:short) %(symref)' refs/remotes 2>/dev/null \
    | awk '$2==""{print $1}'
}

# All branches to scan: remote-tracking PLUS local heads (catches local-only
# branches and repos with no remote). Deduplicated.
scan_branches() {
  { git for-each-ref --format='%(refname:short) %(symref)' refs/remotes 2>/dev/null | awk '$2==""{print $1}'
    git for-each-ref --format='%(refname:short)' refs/heads 2>/dev/null
  } | awk 'NF && !seen[$0]++'
}

# Clean default branch ref of the repo in CWD, e.g. origin/main or origin/master.
default_branch_ref() {
  local r c
  r="$(git symbolic-ref --quiet refs/remotes/origin/HEAD 2>/dev/null)"
  [ -n "$r" ] && { echo "${r#refs/remotes/}"; return; }
  for c in origin/main origin/master; do
    git rev-parse --verify --quiet "$c" >/dev/null 2>&1 && { echo "$c"; return; }
  done
}

# Files containing ANY IOC at a given ref (bare paths, no ref prefix).
infected_files() {
  git grep -lIE "$IOC_RE" "$1" 2>/dev/null | sed "s#^${1}:##"
}

# Space-separated labels of which IOCs match at a ref (for the scan report).
ioc_labels() {
  local ref="$1" out=""
  git grep -qIE '_\$_' "$ref" 2>/dev/null && out="$out loader"
  git grep -qI "$C2_DOMAIN" "$ref" 2>/dev/null && out="$out C2-url"
  git grep -qI 'AUTH_API_KEY' "$ref" 2>/dev/null && out="$out AUTH_API_KEY"
  git grep -qI 'Auth Error!' "$ref" 2>/dev/null && out="$out eval-backdoor"
  printf '%s' "${out# }"
}

# Heuristic (dual-use) signal: tracked files that call eval(. NOT auto-cleaned —
# eval() is legitimate in some code — but surfaced for manual review since it is
# the execution primitive of the C2 backdoor.
EVAL_RE='eval[[:space:]]*\('
eval_files() {
  git grep -lIE "$EVAL_RE" "$1" 2>/dev/null | sed "s#^${1}:##"
}

# Working-tree (uncommitted/untracked, on-disk) files matching a pattern. Catches
# a backdoor that was dropped locally but never committed to any branch.
worktree_hits() {
  grep -rIlE --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next \
    --exclude-dir=dist --exclude-dir=build "$1" . 2>/dev/null | sed 's#^\./##'
}

# Does this ref's .gitignore hide config.bat?
gitignore_tampered() {
  git grep -q "$GITIGNORE_BAD" "$1" -- .gitignore 2>/dev/null
}

# Template env files that are MEANT to be committed (no real secrets).
SECRET_SKIP_RE='example|sample|template|dist|\.md$'

# Does the .gitignore AT A REF actually ignore the literal .env file? (a rule
# like `.env*.local` does NOT, so match only patterns that truly cover `.env`.)
env_ref_ignored() {
  git show "$1:.gitignore" 2>/dev/null | grep -vE '^[[:space:]]*#' \
    | grep -qE '^[[:space:]]*(\.env\*?|\.env/|\*\.env)[[:space:]]*$'
}

# Real .env files actually committed at a ref (excludes example/sample templates).
list_tracked_secrets() {
  git ls-tree -r --name-only "$1" 2>/dev/null \
    | grep -E '(^|/)\.env($|\.)' | grep -viE "$SECRET_SKIP_RE"
}

# Ensure the .gitignore in CWD ignores .env files (restores what the malware,
# or sloppy setup, left out). Uses git check-ignore — authoritative, so it isn't
# fooled by partial patterns like `.env*.local`. Keeps .env.example/.sample.
ensure_env_ignored() {
  git check-ignore -q .env 2>/dev/null && return 1   # literal .env already ignored
  printf '\n# local env files (restored by security cleanup)\n.env\n.env.*\n!.env.example\n!.env.sample\n' >> .gitignore
  return 0
}

# Newest commit reachable from $ref that touched $file AND has it free of ALL
# IOCs (so a drizzle-backdoor file is restored to a genuinely clean version).
last_clean_commit() {
  local ref="$1" file="$2" c
  for c in $(git rev-list "$ref" -- "$file" 2>/dev/null); do
    git cat-file -e "$c:$file" 2>/dev/null || continue
    git show "$c:$file" 2>/dev/null | grep -qE "$IOC_RE" || { echo "$c"; return 0; }
  done
  return 1
}

# Last-resort: strip the injected loader out of a working-tree file in place.
# (1) cut the hidden payload that hides after a long run of whitespace on a line,
# (2) drop any line still bearing the marker, (3) remove the injected
# createRequire loader prologue, (4) tidy leading/trailing blank lines.
strip_marker_file() {
  local f="$1"
  local loader_re='^import \{ createRequire \} from .module.;[[:space:]]*$|^const require = createRequire\(import\.meta\.url\);[[:space:]]*$'
  sed -E 's/[[:blank:]]{8,}[^[:blank:]].*$//' "$f" > "$f.__s1"
  grep -vF -- "$MARKER_PLAIN" "$f.__s1" > "$f.__s2"
  grep -vE "$loader_re" "$f.__s2" > "$f.__s3"
  awk 'BEGIN{n=0;st=0}
       { if(!st && $0 ~ /^[[:space:]]*$/) next; st=1; a[++n]=$0 }
       END{ while(n>0 && a[n] ~ /^[[:space:]]*$/) n--; for(i=1;i<=n;i++) print a[i] }' \
       "$f.__s3" > "$f"
  rm -f "$f.__s1" "$f.__s2" "$f.__s3"
}

# Repo in CWD has anything worth cleaning? (env issues count only in --env mode)
repo_has_hit() {
  local b
  while IFS= read -r b; do
    [ -z "$b" ] && continue
    { [ -n "$(infected_files "$b")" ] || gitignore_tampered "$b"; } && return 0
    if [ "${ENV_MODE:-0}" = 1 ]; then
      env_ref_ignored "$b" || return 0
      [ -n "$(list_tracked_secrets "$b")" ] && return 0
    fi
  done < <(remote_branches)
  return 1
}

# ---------------------------------------------------------------------------
# SCAN
# ---------------------------------------------------------------------------
# Returns 0 if the repo is clean, 1 if any branch is infected.
scan_repo() {
  local repo="$1" hit=0 b files
  pushd "$repo" >/dev/null || return 0
  [ "${NOFETCH:-0}" = 1 ] || git fetch --quiet --all 2>/dev/null
  local secrets noenv evals
  while IFS= read -r b; do
    [ -z "$b" ] && continue
    files="$(infected_files "$b" | tr '\n' ' ')"
    secrets="$(list_tracked_secrets "$b" | tr '\n' ' ')"
    noenv=0; env_ref_ignored "$b" || noenv=1
    if [ -n "$files" ] || gitignore_tampered "$b" || [ -n "$secrets" ] || [ "$noenv" = 1 ]; then
      hit=1
      if [ -n "$files" ] || gitignore_tampered "$b"; then
        printf '  %s %-50s ' "$(c_red '●')" "$b"
      else
        printf '  %s %-50s ' "$(c_yel '⚠')" "$b"
      fi
      [ -n "$files" ] && printf 'IOC[%s] in: %s' "$(ioc_labels "$b")" "$files"
      gitignore_tampered "$b" && printf '[.gitignore:config.bat] '
      [ "$noenv" = 1 ] && printf '[.env NOT ignored] '
      [ -n "$secrets" ] && printf '%s' "$(c_red "[committed secret: $secrets]")"
      printf '\n'
    fi
  done < <(scan_branches)

  # Working-tree pass: catch a backdoor dropped on disk but not in any branch.
  local wt_ioc; wt_ioc="$(worktree_hits "$IOC_RE" | tr '\n' ' ')"
  if [ -n "$wt_ioc" ]; then
    hit=1; printf '  %s working-tree IOC on disk: %s\n' "$(c_red '●')" "$wt_ioc"
  fi

  # Heuristic eval() review across branch tips + working tree (deduped).
  evals="$( { eval_files HEAD 2>/dev/null; worktree_hits "$EVAL_RE"; } | awk 'NF&&!s[$0]++' | tr '\n' ' ')"
  if [ -n "$evals" ]; then
    printf '  %s eval( found (confirm manually): %s\n' "$(c_yel 'review')" "$evals"
    REVIEW_LIST+=("$repo: $evals")
  fi

  [ "$hit" -eq 0 ] && [ -z "$evals" ] && printf '  %s clean\n' "$(c_grn '✓')"
  [ "$hit" -eq 0 ] && [ -n "$evals" ] && printf '  %s no malware IOC (eval review only)\n' "$(c_grn '✓')"
  popd >/dev/null
  return $hit
}

cmd_scan() {
  local root="." remote=0 a infected=() repo
  local want_list=0
  for a in "$@"; do
    if [ "$want_list" = 1 ]; then LIST_FILE="$a"; want_list=0; continue; fi
    case "$a" in
      --remote) remote=1 ;;
      --list) want_list=1 ;;
      --list=*) LIST_FILE="${a#*=}" ;;
      --owner=*) remote=1; OWNER_FILTER="${a#*=}" ;;
      --mine) remote=1; OWNER_FILTER="$(gh api user --jq .login 2>/dev/null)" ;;
      *) root="$a" ;;
    esac
  done
  REVIEW_LIST=()
  root="$(resolve_root "$remote" "$root")" || exit $?
  hr; echo "SCAN  root=$root  remote=$remote"; hr
  while IFS= read -r repo; do
    [ -z "$repo" ] && continue
    echo "$(c_yel 'repo:') $repo"
    scan_repo "$repo" || infected+=("$repo")
  done < <(find_repos "$root")
  hr
  if [ "${#infected[@]}" -eq 0 ]; then
    echo "$(c_grn 'No infected repos found.')"
  else
    echo "$(c_red "Infected repos (${#infected[@]}):")"; printf '  - %s\n' "${infected[@]}"
    echo
    if [ -n "$LIST_FILE" ]; then
      echo "Fix them with:  clean-injected-loader clean --list $LIST_FILE --push"
    elif [ "$remote" = 1 ]; then
      echo "Fix them with:  clean-injected-loader clean --remote --push"
    else
      echo "Fix them with:  clean-injected-loader clean $root --push"
    fi
  fi
  if [ "${#REVIEW_LIST[@]}" -gt 0 ]; then
    echo; echo "$(c_yel "eval() to review manually (${#REVIEW_LIST[@]}):")"
    printf '  - %s\n' "${REVIEW_LIST[@]}"
  fi
}

# ---------------------------------------------------------------------------
# CLEAN
# ---------------------------------------------------------------------------
# Operates inside a worktree. $1 = remote branch ref (origin/foo). Uses a
# uniquely-named temp branch so it never collides with a branch that is already
# checked out in the user's main worktree (e.g. main).
clean_branch() {
  local rb="$1" orig="${1#origin/}"
  local tmp="injfix-$(printf '%s' "$orig" | tr '/' '-')"
  local files f src defref

  files="$(infected_files "$rb")"
  gitignore_tampered "$rb" && files="$files
.gitignore"
  local has_files=0
  [ -n "$(printf '%s' "$files" | tr -d '[:space:]')" ] && has_files=1
  # Nothing to do unless there are tampered files, or we're in --env mode.
  [ "$has_files" = 0 ] && [ "${ENV_MODE:-0}" != 1 ] && return 1

  git reset --hard --quiet 2>/dev/null
  git checkout --quiet -B "$tmp" "$rb" || return 1
  defref="$(default_branch_ref)"

  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if [ "$f" = ".gitignore" ]; then
      grep -vF -- "$GITIGNORE_BAD" .gitignore > .gitignore.__t && mv .gitignore.__t .gitignore
      printf '      %-26s stripped %s line\n' ".gitignore" "$GITIGNORE_BAD"
    elif src="$(last_clean_commit "$rb" "$f")"; then
      git show "$src:$f" > "$f"
      printf '      %-26s restored from %s (last clean on branch)\n' "$f" "${src:0:8}"
    elif [ -n "$defref" ] && [ "$defref" != "$rb" ] \
         && git cat-file -e "$defref:$f" 2>/dev/null \
         && ! git show "$defref:$f" 2>/dev/null | grep -qE "$IOC_RE"; then
      git show "$defref:$f" > "$f"
      printf '      %-26s restored from clean %s\n' "$f" "$defref"
    elif grep -qF -- "$MARKER_PLAIN" "$f" 2>/dev/null; then
      # only the obfuscated loader can be safely stripped in place
      strip_marker_file "$f"
      printf '      %-26s loader stripped in place; result below:\n' "$f"
      sed 's/^/          | /' "$f"
    else
      # eval/C2 backdoor with no clean ancestor — refuse to guess; flag it.
      printf '      %s %s: no clean version in history — MANUAL REVIEW REQUIRED\n' "$(c_red 'SKIP')" "$f"
    fi
  done < <(printf '%s\n' "$files")

  # Restore .env ignore rules the malware (or a tampered setup) stripped out.
  if ensure_env_ignored; then
    printf '      %-26s restored .env ignore rules\n' ".gitignore"
  fi

  # Optionally untrack real .env secrets that got committed (keeps the local
  # file; does NOT scrub history — rotate those secrets regardless). After
  # removing from the index we make sure the path is genuinely ignored, so the
  # `git add -A` below cannot silently re-add it.
  if [ "${UNTRACK_SECRETS:-0}" = 1 ]; then
    local s
    while IFS= read -r s; do
      [ -z "$s" ] && continue
      git rm --cached --quiet "$s" 2>/dev/null || continue
      git check-ignore -q "$s" 2>/dev/null || printf '%s\n' "$s" >> .gitignore
      printf '      %s untracked committed secret: %s\n' "$(c_yel '!')" "$s"
    done < <(git ls-files | grep -E '(^|/)\.env($|\.)' | grep -viE "$SECRET_SKIP_RE")
  fi

  git add -A
  # Honor the user's signing setup so the fix commit shows "Verified" on GitHub.
  # --no-verify still skips repo hooks (never run a poisoned repo's hooks), which
  # does NOT affect signing.
  local signflag='-c commit.gpgsign=false'
  [ "${SIGN_COMMITS:-0}" = 1 ] && signflag='-c commit.gpgsign=true'
  if ! git $signflag commit --no-verify --quiet \
        -m "fix(security): strip injected loader, restore .env ignore, untrack secrets" \
        >/dev/null 2>&1; then
    printf '      (no changes to commit)\n'; return 1
  fi

  if git grep -qIE "$IOC_RE" HEAD 2>/dev/null \
     || git grep -q "$GITIGNORE_BAD" HEAD -- .gitignore 2>/dev/null; then
    printf '      %s IOC still present after clean — left for manual review!\n' "$(c_red 'FAIL')"; return 1
  fi
  printf '      %s verified clean\n' "$(c_grn '✓')"
  FIXED_MAP+=("$tmp:$orig")
  return 0
}

clean_repo() {
  local repo="$1" push="$2" name wt rb pair tmp orig
  repo="$(cd "$repo" && pwd)"; name="$(basename "$repo")"; wt="$WORKSPACE/$name"

  rm -rf "$wt"; git -C "$repo" worktree prune 2>/dev/null
  echo "  worktree -> $wt"
  git -C "$repo" worktree add --detach --quiet "$wt" || { echo "  worktree failed"; return; }

  FIXED_MAP=()
  pushd "$wt" >/dev/null
  while IFS= read -r rb; do
    [ -z "$rb" ] && continue
    local do_it=0
    { [ -n "$(infected_files "$rb")" ] || gitignore_tampered "$rb"; } && do_it=1
    if [ "${ENV_MODE:-0}" = 1 ]; then
      env_ref_ignored "$rb" || do_it=1
      [ -n "$(list_tracked_secrets "$rb")" ] && do_it=1
    fi
    [ "$do_it" = 0 ] && continue
    echo "    fixing $rb"
    clean_branch "$rb"
  done < <(remote_branches)
  git checkout --quiet --detach 2>/dev/null   # free temp branches for push/delete
  popd >/dev/null
  git -C "$repo" worktree remove --force "$wt" 2>/dev/null

  if [ "${#FIXED_MAP[@]}" -eq 0 ]; then echo "    nothing to fix"; return; fi

  if [ "$push" = "1" ]; then
    for pair in "${FIXED_MAP[@]}"; do
      tmp="${pair%%:*}"; orig="${pair#*:}"
      if git -C "$repo" push origin "$tmp:refs/heads/$orig"; then
        echo "      $(c_grn 'pushed') -> origin/$orig"
      else
        echo "      $(c_red 'push FAILED') -> origin/$orig"
      fi
      git -C "$repo" branch -D "$tmp" >/dev/null 2>&1
    done
    # refresh the user's local checkout so it isn't left stale on the old (still
    # infected) commit. Safe fast-forward; skips dirty/diverged trees.
    [ "${RESYNC:-1}" = 1 ] && resync_repo "$repo" 1 0
  else
    echo "    $(c_grn 'fixed locally') (not pushed). Push each when ready:"
    for pair in "${FIXED_MAP[@]}"; do
      tmp="${pair%%:*}"; orig="${pair#*:}"
      echo "      git -C $repo push origin $tmp:$orig"
    done
  fi
}

cmd_clean() {
  local root="." push=0 remote=0 a repo
  # .env restore + secret untracking are ON by default; opt out with the flags.
  # After --push, also resync the local checkout (RESYNC); opt out with --no-resync.
  ENV_MODE=1; UNTRACK_SECRETS=1; RESYNC=1
  # Sign cleanup commits when global signing is configured (so they're Verified);
  # --sign forces it on, --no-sign forces it off.
  local sign=auto want_list=0
  for a in "$@"; do
    if [ "$want_list" = 1 ]; then LIST_FILE="$a"; want_list=0; continue; fi
    case "$a" in
      --push) push=1 ;;
      --remote) remote=1 ;;
      --list) want_list=1 ;;
      --list=*) LIST_FILE="${a#*=}" ;;
      --owner=*) remote=1; OWNER_FILTER="${a#*=}" ;;
      --mine) remote=1; OWNER_FILTER="$(gh api user --jq .login 2>/dev/null)" ;;
      --sign) sign=on ;;
      --no-sign) sign=off ;;
      --env) ENV_MODE=1 ;;
      --untrack-secrets) ENV_MODE=1; UNTRACK_SECRETS=1 ;;
      --no-untrack|--keep-secrets) UNTRACK_SECRETS=0 ;;
      --no-env) ENV_MODE=0; UNTRACK_SECRETS=0 ;;
      --no-resync) RESYNC=0 ;;
      *) root="$a" ;;
    esac
  done
  SIGN_COMMITS=0
  case "$sign" in
    on) SIGN_COMMITS=1 ;;
    auto) signing_configured && SIGN_COMMITS=1 ;;
  esac
  root="$(resolve_root "$remote" "$root")" || exit $?
  mkdir -p "$WORKSPACE"
  hr; echo "CLEAN root=$root  remote=$remote  push=$push  sign=$SIGN_COMMITS  env=$ENV_MODE  untrack=$UNTRACK_SECRETS  workspace=$WORKSPACE"; hr
  while IFS= read -r repo; do
    [ -z "$repo" ] && continue
    pushd "$repo" >/dev/null
    if [ "${NOFETCH:-0}" != 1 ] || [ "$push" = 1 ]; then
      ensure_key_loaded "$(git remote get-url origin 2>/dev/null)"
    fi
    [ "${NOFETCH:-0}" = 1 ] || git fetch --quiet --all 2>/dev/null
    local hit=1; repo_has_hit && hit=0
    # local-only staleness: remote clean but local branch/working tree still dirty
    local localdirty=0
    if [ "$hit" -ne 0 ]; then
      { [ -n "$(infected_files HEAD)" ] || [ -n "$(worktree_hits "$IOC_RE")" ]; } && localdirty=1
    fi
    popd >/dev/null
    if [ "$hit" -eq 0 ]; then
      echo "$(c_yel 'repo:') $repo"
      NOFETCH=1 clean_repo "$repo" "$push"
    elif [ "${RESYNC:-1}" = 1 ] && [ "$localdirty" = 1 ]; then
      # nothing to fix on the remote, but the local checkout is stale & infected —
      # refresh it from the already-clean remote.
      echo "$(c_yel 'repo:') $repo (remote clean; local stale — resyncing)"
      resync_repo "$repo" 0 0
    fi
  done < <(find_repos "$root")
  hr
  if [ -n "$LIST_FILE" ]; then
    echo "Done. Re-run 'clean-injected-loader scan --list $LIST_FILE' to confirm all branches are clean."
    [ "$push" = 1 ] && echo "Refresh your local checkouts:  clean-injected-loader resync ~/dev --fetch"
  elif [ "$remote" = 1 ]; then
    echo "Done. Re-run 'clean-injected-loader scan --remote' to confirm all branches are clean."
    [ "$push" = 1 ] && echo "Refresh your local checkouts:  clean-injected-loader resync ~/dev --fetch"
  else
    echo "Done. Re-run 'clean-injected-loader scan $root' to confirm all branches are clean."
  fi
}

# ---------------------------------------------------------------------------
# PURGE  (history rewrite — scrubs the malware out of the commits themselves)
# ---------------------------------------------------------------------------
# Writes the per-commit cleaner that filter-branch runs against every commit's
# checked-out tree. It strips the loader from any marker-bearing file, removes
# config.bat from every .gitignore, and (when TREECLEAN_UNTRACK=1) deletes real
# .env secrets so they vanish from history.
write_cleaner() {
  local f="$WORKSPACE/_treeclean.sh"
  cat > "$f" <<'CLEANER'
#!/usr/bin/env bash
set -u
MARKER='_$_'
loader_re='^import \{ createRequire \} from .module.;[[:space:]]*$|^const require = createRequire\(import\.meta\.url\);[[:space:]]*$'

# 1) strip the injected loader from every file that carries the marker
grep -rIlF -- "$MARKER" . 2>/dev/null | while IFS= read -r f; do
  [ -f "$f" ] || continue
  sed -E 's/[[:blank:]]{8,}[^[:blank:]].*$//' "$f" > "$f.__s1"
  grep -vF -- "$MARKER" "$f.__s1" > "$f.__s2"
  grep -vE "$loader_re" "$f.__s2" > "$f.__s3"
  awk 'BEGIN{n=0;st=0}{if(!st&&$0~/^[[:space:]]*$/)next;st=1;a[++n]=$0}
       END{while(n>0&&a[n]~/^[[:space:]]*$/)n--;for(i=1;i<=n;i++)print a[i]}' "$f.__s3" > "$f"
  rm -f "$f.__s1" "$f.__s2" "$f.__s3"
done

# 2) remove config.bat from every .gitignore, and restore .env ignore rules
#    (matches `clean`: add a real .env rule wherever one isn't already present)
find . -name .gitignore -type f 2>/dev/null | while IFS= read -r gi; do
  grep -vF -- 'config.bat' "$gi" > "$gi.__t" && mv "$gi.__t" "$gi"
  if ! grep -qE '^[[:space:]]*(\.env\*?|\.env/|\*\.env)[[:space:]]*$' "$gi"; then
    printf '\n# local env files (restored by security cleanup)\n.env\n.env.*\n!.env.example\n!.env.sample\n' >> "$gi"
  fi
done

# 3) optional: erase real .env secrets from history (keep *.example/.sample)
if [ "${TREECLEAN_UNTRACK:-0}" = 1 ]; then
  find . -type f \( -name '.env' -o -name '.env.*' \) 2>/dev/null \
    | grep -viE 'example|sample|template|dist' \
    | while IFS= read -r s; do rm -f "$s"; done
fi
exit 0
CLEANER
  echo "$f"
}

purge_repo() {
  local repo="$1" url="$2" push="$3" name work rb b cleaner
  repo="$(cd "$repo" && pwd)"
  name="$(basename "$repo")"; work="$WORKSPACE/purge-$name"
  cleaner="$WORKSPACE/_treeclean.sh"
  rm -rf "$work"
  echo "  cloning origin (isolated) -> $work"
  git clone --quiet "$url" "$work" || { echo "  $(c_red 'clone failed') (need network/SSH auth)"; return; }

  pushd "$work" >/dev/null
  # materialize a local branch for every remote branch so --branches rewrites all
  while IFS= read -r rb; do
    [ -z "$rb" ] && continue
    git branch -f "${rb#origin/}" "$rb" >/dev/null 2>&1
  done < <(remote_branches)

  echo "  rewriting history (filter-branch, all branches)…"
  # A rewrite changes every SHA, so any pre-existing signature is invalidated.
  # When signing is configured, re-sign each rewritten commit via a commit-filter
  # (git commit-tree -S) so the new history is "Verified" on GitHub, not unsigned.
  local commit_filter='git commit-tree "$@"'
  if [ "${SIGN_COMMITS:-0}" = 1 ]; then
    commit_filter='git commit-tree -S "$@"'
    echo "  (re-signing every rewritten commit — slower; honors your signing key)"
  fi
  FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch --force \
    --tree-filter "TREECLEAN_UNTRACK=${UNTRACK_SECRETS:-0} bash '$cleaner'" \
    --commit-filter "$commit_filter" \
    -- --branches >/dev/null 2>&1 || { echo "  $(c_red 'filter-branch failed')"; popd >/dev/null; return; }

  # verify every local branch is clean
  local bad=0
  while IFS= read -r b; do
    [ -z "$b" ] && continue
    if git grep -qIE "$IOC_RE" "$b" 2>/dev/null || git grep -q "$GITIGNORE_BAD" "$b" -- .gitignore 2>/dev/null; then
      echo "      $(c_red 'STILL DIRTY'): $b (eval/C2 backdoor needs a branch reset to a clean commit — see report)"; bad=1
    fi
  done < <(git for-each-ref --format='%(refname:short)' refs/heads)
  [ "$bad" = 0 ] && echo "      $(c_grn '✓') all branches verified clean after rewrite"

  if [ "$push" = "1" ]; then
    echo "  force-pushing rewritten branches…"
    while IFS= read -r b; do
      [ -z "$b" ] && continue
      if git push --force-with-lease origin "$b" 2>/dev/null; then
        echo "      $(c_grn 'force-pushed') $b"
      else
        echo "      $(c_red 'push FAILED') $b (try --force if branch protection/lease blocks it)"
      fi
    done < <(git for-each-ref --format='%(refname:short)' refs/heads)
  else
    echo "  $(c_yel 'rewrite done in isolated clone — NOT pushed.')"
    echo "  inspect:  git -C $work log --oneline --all"
    echo "  when satisfied, re-run with --push to force-push the rewritten history."
  fi
  popd >/dev/null
  # after a force-push the user's local checkout has diverged from the rewritten
  # remote — hard-resync it (still skips a dirty tree to avoid losing live work).
  if [ "$push" = "1" ] && [ "${RESYNC:-1}" = 1 ]; then
    echo "  resyncing local checkout to rewritten remote:"
    resync_repo "$repo" 1 1
  fi
}

cmd_purge() {
  local root="." push=0 remote=0 a repo url
  # erasing committed secrets from history is ON by default; opt out with the flag.
  # After --push (force-push), also hard-resync the local checkout; --no-resync skips.
  ENV_MODE=1; UNTRACK_SECRETS=1; RESYNC=1
  local sign=auto want_list=0
  for a in "$@"; do
    if [ "$want_list" = 1 ]; then LIST_FILE="$a"; want_list=0; continue; fi
    case "$a" in
      --push) push=1 ;;
      --remote) remote=1 ;;
      --list) want_list=1 ;;
      --list=*) LIST_FILE="${a#*=}" ;;
      --owner=*) remote=1; OWNER_FILTER="${a#*=}" ;;
      --mine) remote=1; OWNER_FILTER="$(gh api user --jq .login 2>/dev/null)" ;;
      --sign) sign=on ;;
      --no-sign) sign=off ;;
      --untrack-secrets) UNTRACK_SECRETS=1 ;;
      --env) ENV_MODE=1 ;;
      --no-untrack|--keep-secrets) UNTRACK_SECRETS=0 ;;
      --no-resync) RESYNC=0 ;;
      *) root="$a" ;;
    esac
  done
  SIGN_COMMITS=0
  case "$sign" in
    on) SIGN_COMMITS=1 ;;
    auto) signing_configured && SIGN_COMMITS=1 ;;
  esac
  root="$(resolve_root "$remote" "$root")" || exit $?
  mkdir -p "$WORKSPACE"; write_cleaner >/dev/null
  hr; echo "PURGE root=$root  remote=$remote  push=$push  sign=$SIGN_COMMITS  untrack=$UNTRACK_SECRETS"; hr
  echo "$(c_red 'WARNING:') purge REWRITES git history (every affected commit gets a new SHA)."
  echo "It works on an isolated clone; with --push it FORCE-PUSHES. Collaborators must"
  echo "re-clone afterward, and any leaked secret must still be ROTATED (old commits may"
  echo "linger on the host/forks even after the rewrite)."
  echo
  while IFS= read -r repo; do
    [ -z "$repo" ] && continue
    pushd "$repo" >/dev/null
    url="$(git remote get-url origin 2>/dev/null)"
    ensure_key_loaded "$url"                       # one passphrase, then silent
    [ "${NOFETCH:-0}" = 1 ] || git fetch --quiet --all 2>/dev/null
    local hit=1; repo_has_hit && hit=0
    popd >/dev/null
    [ "$hit" -ne 0 ] && continue
    echo "$(c_yel 'repo:') $repo"
    purge_repo "$repo" "$url" "$push"
  done < <(find_repos "$root")
  hr
  if [ -n "$LIST_FILE" ]; then
    echo "Done. Re-run 'clean-injected-loader scan --list $LIST_FILE' (after pushing) to confirm."
    [ "$push" = 1 ] && echo "Refresh your local checkouts:  clean-injected-loader resync ~/dev --fetch --hard"
  elif [ "$remote" = 1 ]; then
    echo "Done. Re-run 'clean-injected-loader scan --remote' (after pushing) to confirm."
    [ "$push" = 1 ] && echo "Refresh your local checkouts:  clean-injected-loader resync ~/dev --fetch --hard"
  else
    echo "Done. Re-run 'clean-injected-loader scan $root' (after pushing) to confirm."
  fi
}

# ---------------------------------------------------------------------------
# RESYNC  (pull local checkouts up to the already-cleaned remote)
# ---------------------------------------------------------------------------
# For each repo, fast-forward the current local branch to its origin upstream so
# a stale local working tree (still holding the loader) is replaced by the clean
# remote version. Safe by default: --ff-only never discards committed work and
# skips repos with uncommitted changes or diverged history. Uses the already-
# fetched origin refs (no network) unless --fetch is given; --hard force-resets
# diverged branches (destructive, opt-in).
resync_repo() {
  local repo="$1" fetch="$2" hard="$3" cur up
  repo="$(cd "$repo" && pwd)"
  pushd "$repo" >/dev/null || return
  if [ "$fetch" = 1 ]; then
    ensure_key_loaded "$(git remote get-url origin 2>/dev/null)"
    git fetch --quiet origin 2>/dev/null
  fi
  cur="$(git symbolic-ref --quiet --short HEAD 2>/dev/null)"
  if [ -z "$cur" ]; then echo "  $(c_yel 'skip') $repo (detached HEAD)"; popd >/dev/null; return; fi
  up="origin/$cur"
  if ! git rev-parse --verify --quiet "$up" >/dev/null 2>&1; then
    echo "  $(c_yel 'skip') $repo ($cur has no $up)"; popd >/dev/null; return
  fi
  if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    echo "  $(c_yel 'skip') $repo ($cur has uncommitted changes — stash first)"; popd >/dev/null; return
  fi
  local local_sha up_sha; local_sha="$(git rev-parse "$cur")"; up_sha="$(git rev-parse "$up")"
  if [ "$local_sha" = "$up_sha" ]; then
    echo "  $(c_grn 'up-to-date') $repo ($cur)"
  elif git merge-base --is-ancestor "$cur" "$up" 2>/dev/null; then
    git merge --ff-only --quiet "$up" && echo "  $(c_grn 'fast-forwarded') $repo ($cur -> ${up_sha:0:8})"
  elif [ "$hard" = 1 ]; then
    git reset --hard --quiet "$up" && echo "  $(c_red 'hard-reset') $repo ($cur -> ${up_sha:0:8}, local commits dropped)"
  else
    echo "  $(c_yel 'diverged') $repo ($cur has local commits not on $up — use --hard or rebase manually)"
  fi
  popd >/dev/null
}

cmd_resync() {
  local root="." fetch=0 hard=0 a
  for a in "$@"; do
    case "$a" in
      --fetch) fetch=1 ;;
      --hard) hard=1 ;;
      *) root="$a" ;;
    esac
  done
  root="$(require_dir "$root")" || exit $?
  hr; echo "RESYNC root=$root  fetch=$fetch  hard=$hard"; hr
  local repo
  while IFS= read -r repo; do
    [ -z "$repo" ] && continue
    resync_repo "$repo" "$fetch" "$hard"
  done < <(find_repos "$root")
  hr; echo "Done. Local checkouts now match the cleaned remote (where fast-forward was safe)."
}

main() {
  local cmd="${1:-scan}"; shift || true
  case "$cmd" in
    scan)   cmd_scan   "$@" ;;
    clean)  cmd_clean  "$@" ;;
    purge)  cmd_purge  "$@" ;;
    resync) cmd_resync "$@" ;;
    *) echo "usage: clean-injected-loader {scan|clean|purge|resync} [ROOT_DIR] [opts]"
       echo "  scan    read-only report (loader+eval/C2 IOCs, eval() review, .env, secrets;"
       echo "          covers remote AND local branches AND the working tree)"
       echo "  clean   add a clean-up commit on top (safe, no history rewrite)"
       echo "  purge   rewrite history so the malware was never in the commits (destructive)"
       echo "  resync  (standalone) fast-forward stale local checkouts to the cleaned remote"
       echo "            [--fetch fetch first] [--hard force-reset diverged branches]"
       echo
       echo "  --list FILE  run against exactly the repos listed in FILE (one per line,"
       echo "            full git URL or owner/name; # comments + blank lines ok). Clones"
       echo "            each into the workspace, then scan/clean/purge them. Transparent"
       echo "            (you review the list) and needs no gh. Build the list by hand or:"
       echo "              gh repo list YOUR-ACCOUNT --limit 300 --json sshUrl -q '.[].sshUrl' > repos.txt"
       echo "  --remote  run against EVERY repo on github.com/settings/repositories"
       echo "            (owned + collaborator + org), auto-enumerated via 'gh' and cloned"
       echo "            into the workspace. Like --list but for the whole account at once."
       echo "            Needs the 'gh' CLI authenticated with 'repo' scope. After a cloned"
       echo "            clean/purge --push, refresh local copies with:"
       echo "              clean-injected-loader resync ~/dev --fetch"
       echo "  --mine        scope --remote to repos YOU own (skips collaborator/org repos)"
       echo "  --owner=a,b   scope --remote to the given owners only (implies --remote)"
       echo "  --sign/--no-sign  force signing of fix/purge commits on or off"
       echo "            (default: auto — signs when commit.gpgsign=true + a signing"
       echo "             key are configured, so commits show 'Verified' on GitHub)"
       echo
       echo "  After --push, clean & purge AUTO-RESYNC your local checkout to the cleaned"
       echo "  remote (clean: fast-forward; purge: hard reset) so it isn't left stale."
       echo "  By default clean & purge also restore .env ignore rules and untrack/erase"
       echo "  committed .env secrets. Opt out with:"
       echo "    --no-untrack     keep committed .env files tracked (still restores ignore rules)"
       echo "    --no-env         skip all .env handling (clean only; malware-only cleanup)"
       echo "    --no-resync      do not touch the local checkout after pushing"
       echo "    --push           push (clean) / force-push (purge) the result"
       exit 1 ;;
  esac
}
main "$@"
