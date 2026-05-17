# Reverge — Claude working agreement

## Test-driven development (mandatory)

For **every new piece of functionality**, follow the red → green loop in this order:

1. **Write a failing test first** that captures the behavior you intend to add. Put it under [src/tests/](src/tests/) alongside related tests.
2. **Run the test and confirm it fails** — typically `venv/bin/pytest src/tests/path/to/test_file.py::test_name -x`. The failure must be from the assertion or missing behavior, **not** from a syntax error or unresolved import. If the test errors before reaching the assertion, fix the test until it reaches the assertion and fails there.
3. **Write the minimum production code** required to make that test pass. No surrounding cleanup, no extra abstractions, no anticipated-future-need scaffolding.
4. **Run the test again and confirm it passes.** Then run the broader suite (`make test` or `venv/bin/pytest src/tests`) to confirm you haven't regressed anything else.

This applies to:
- new functions, methods, routes, classes
- new branches added to existing functions when they implement new behavior (a new flag, a new return path, a new error case)
- bug fixes — the bug becomes the failing test, the fix is what turns it green

It does **not** apply to:
- pure refactors that preserve behavior (rename, extract, inline). The existing suite is the safety net.
- formatting, linting, type-hint additions
- updating dependencies, configuration, docs

When TDD is genuinely impractical (touching code with no reachable test fixture, working in a layer that the suite cannot exercise), say so out loud before writing the production code — don't silently skip the test.

## Fixing bugs uncovered while writing tests (mandatory)

When writing coverage tests reveals a real production bug — code that crashes, raises the wrong exception, references a missing attribute, returns a wrong value, etc. — **fix the bug**. Do not delete the test, mark it `xfail`, comment it out, "work around" it, or move on after noting it in a doc. The point of writing tests is to discover and fix bugs; deferring fixes defeats the exercise and turns the coverage metric into a vanity number.

Concrete rules:

1. **Stop and fix in the same batch.** When a test you just wrote reveals a bug, the bug fix is now part of that batch — not a future TODO. Pause feature/coverage work, fix the production code, and verify the original test passes for the right reason.
2. **Never delete a test because it crashed the code.** A test that triggers an unhandled exception or AttributeError in production code has done its job — it found a real bug. Keep the test, fix the code.
3. **Never silently note a bug and continue.** If you see something broken while reading code (UnboundLocalError, wrong attribute name, dead branch, missing None-guard, etc.), open a TODO item, write a failing test, and fix it.
4. **Bug-fix commit shape.** One commit per bug. Message: `fix(<area>): <one-line description>`. Body: what the bug was, how it manifested, and the minimum production change. The failing-test → fix → green cycle in one commit, so future bisect points at the right place.
5. **Don't shelve bugs to handoff docs.** Handoff docs are for context and gotchas, not unfixed bugs. If you record a bug, also link to the commit that fixed it (or open a tracking issue if it's genuinely out of scope and you've checked with the user).

Workarounds are allowed only when (a) the bug is in a third-party dependency you can't patch, or (b) the user has explicitly told you to defer the fix. State the workaround and the reason out loud, in the test file and in the commit message.

## Test-running conventions in this repo

- Tests live in [src/tests/](src/tests/). Run them from the repo root: `venv/bin/pytest src/tests`.
- Runtime deps live in the existing `venv/`. Dev tooling (ruff, ty) lives in `.venv/` via `uv sync --group dev`.
- The DB fixture is session-scoped and spins up a real `mysql-test` Docker container. Tests share that DB, so use unique row names (e.g. `api.host-tools.example.com`, not `api.example.com`) and clean up at the end of each test.
- Cloud-touching tests (real AWS deploys) are marked `@pytest.mark.requires_cloud_creds` and auto-skipped when no AWS credentials are configured.
- See [Makefile](Makefile) for the canonical targets (`make test`, `make test-cov`, `make lint`, `make format`, etc.).

## Pre-commit checks (mandatory)

CI runs `make ci` (format-check + lint + test) on every push. Catch the cheap failures locally before they cost a CI cycle. **Before every commit that touches `.py` files**, run:

```
ruff format reverge_collector tests
ruff check --fix reverge_collector tests
```

Then `git add` the result and commit. Both commands must exit clean before the commit goes out — `ruff format --check` and `ruff check` are the gates CI enforces. If `ruff check` leaves errors that aren't auto-fixable (E731 `lambda`-as-assignment, `B904` raise-from, etc.), fix them by hand rather than silencing the rule.

This is a hard requirement; don't skip it because the change "looks small." The two formatter/lint cycles together take under a second on this repo, and one CI red push wastes more time than every pre-commit run combined.

## Tooling

- **Formatter & linter:** ruff (`make format`, `make lint`). Don't reach for autopep8/black/isort.
- **Package manager:** `uv` for dev tooling, plain `pip`/`venv` for runtime deps. Don't migrate the runtime venv to uv without discussion.
- **Type checker:** `ty` (alpha) via `make typecheck`. Diagnostics are noisy; treat as informational, not gating.
