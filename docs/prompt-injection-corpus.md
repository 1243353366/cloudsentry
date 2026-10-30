# Optional local prompt-injection corpus tests

The linked Prompt Injection Database is a third-party service. This feature does not install anything into its website, rewrite its pages, submit a pattern, scan customer prompts with its API or attack any service. No full database was acquired or redistributed.

The [public documentation](https://www.promptinjectiondatabase.com/docs/) requires API-key authentication and describes downloadable/API data. The [search page](https://www.promptinjectiondatabase.com/tools/search.php) restricts database access to verified subscription accounts. The [published terms](https://www.promptinjectiondatabase.com/terms.php) restrict automated access and reuse; their branding is inconsistent with the database, so confirm the applicable agreement with the operator. The [about page](https://www.promptinjectiondatabase.com/about.php) describes community contributions. None establishes permission to scrape the whole website or install a tool there.

## User-triggered local option

The repository provides **original synthetic examples**, not copied proprietary database entries:

```sh
python3 scripts/test-mirror-corpus.py \
  --corpus examples/prompt-injection-corpus.jsonl --consent
```

Run this only when you explicitly choose to exercise the local mirror. Without `--consent`, an interactive invocation asks fresh default-deny permission; decline/EOF/non-interactive missing permission stops before reading the corpus or starting a socket. No option is enabled by login, scanning, training or a detection result.

A customer may instead select a **lawfully obtained local export** after confirming its use rights. Convert selected cases into JSONL objects containing one `text`, `prompt` or `example` string. Do not insert credentials or private records. Do not copy unrelated site pages or regex rules; the runner does not compile arbitrary patterns, recursively decode content, fetch a URL embedded in a case or import executable fixtures.

Input is bounded: a 128 KiB regular file, at most 16 records, at most 2,048 UTF-8 bytes per selected text. Oversized, malformed or ambiguous cases are rejected rather than silently promoted to an all-clear. Use a deliberate representative subset; full-database coverage is **not** claimed.

## What the test actually establishes

The runner creates one short-lived **internal loopback-only** mirror, sends each selected case as inert bytes to that mirror and closes it afterward. There is no external host/port option. Source/line/input/response hashes, byte counts and exact-echo results form the report; raw prompts are not printed or saved. The server-side mirror never opens a callback or executes input. The test client is an explicit local test connection, not a reverse shell.

Exact reflection means the bounded mirror returned the same bytes on the same socket. It does **not** mean a model classified the injection, that an LLM is jailbreak-proof, that the visitor's automation was defeated or that the customer's host is guaranteed safe. There is no infinite loop, OCR-interference payload, forced remote investigation, third-party replay or remote-cost objective. A failed test remains a regression failure, not proof of an attack.

The behavior trainer remains independent: [security behavior and customer reports](security-behavior.md) use a fixed trusted corpus and review-only policy. Imported prompts cannot grant approval or teach production rules automatically. Preserve customer evidence separately from research fixtures.

## Contribution draft

A review-only outreach draft is delivered separately. It asks maintainers whether a research-tool integration is appropriate and what licensing/attribution is required. No contribution or contact was sent. Actual external submission needs the customer's separate review and authorization; it is not part of running these local tests.
