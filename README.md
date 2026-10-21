# Sevra-Bench: Social Engineering of Vulnerabilities in Review Agents

[![Paper](https://img.shields.io/badge/arXiv-2606.13757-b31b1b)](https://arxiv.org/abs/2606.13757)
[![Project page](https://img.shields.io/badge/project-page-2563eb)](https://rufimelo99.github.io/sevra-bench/)
[![Traces](https://img.shields.io/badge/review-traces-2563eb)](https://rufimelo99.github.io/sevra-bench/traces/)
[![Dataset](https://img.shields.io/badge/%F0%9F%A4%97-RedAI4Code%2FSEVRA-yellow)](https://huggingface.co/datasets/RedAI4Code/SEVRA)

**Accepted at [FLMSec 2026](https://flmsec.github.io/) (Foundations of Language Model Security), a NeurIPS 2026 workshop in Paris, France.** 

Can an automated code reviewer reject a malicious pull request when the attacker controls both the code diff **and** the PR narrative?

Sevra-Bench places an LLM review agent in the role of an open-source maintainer, inside a live Gitea instance, and asks it to approve or reject pull requests that reintroduce real, publicly disclosed vulnerabilities under one of 15 social-engineering framings.

![Sevra-Bench pipeline](docs/static/images/fse/fig1_pipeline.png)

## What it measures

Each malicious PR is built from a historical commit that fixed a CVE-linked vulnerability. We automatically reverse the fix, restoring the original vulnerable code, and submit it as a PR whose title and description are written to mask the change. The reviewer sees only what the PR interface exposes (repository state, diff, commit history, PR text) and must decide.

| Metric | Meaning |
|--------|---------|
| **Refusal Rate (RR)** | Fraction of malicious PRs the reviewer rejects. Higher is better. |
| **Security Reason Rate (SRR)** | Of the rejections, the fraction whose rationale (judged by an LLM) identifies the underlying exploit, not a stylistic or unrelated objection. |
| **False-Decline Rate (FDR)** | Fraction of legitimate security fixes the reviewer fails to approve. Guards against reviewers that reject everything. |

### Headline results

Overall Refusal Rate on the retained challenge split (1,062 PRs), plain review prompt, 8 reviewers:

| Reviewer | RR (%) | SRR (%) |
|----------|-------:|--------:|
| Claude Opus 4.7 | 98 | 70 |
| GPT-5.5 | 95 | 70 |
| GLM-5 | 83 | 60 |
| Claude Haiku 4.5 | 53 | 44 |
| DeepSeek V4-Flash | 53 | 33 |
| Kimi K2.5 | 52 | 33 |
| Grok Code Fast | 39 | 18 |
| GPT-5.4-nano | 36 | 37 |

Per-CWE and per-framing breakdowns, the false-decline analysis and example trajectories are in the [paper](https://arxiv.org/abs/2606.13757) and on the [project page](https://rufimelo99.github.io/sevra-bench/).

## Explore the trajectories

The [trace explorer](https://rufimelo99.github.io/sevra-bench/traces/) is a static browser for a curated subset of the evaluation logs: the PR as the reviewer saw it, every model's verdict side by side, and the full reasoning and tool calls behind each one. To rebuild it from your own logs:

```bash
python3 docs/tools/export_traces.py --per-cwe 12 --seed 0   # writes docs/traces/data
python3 -m http.server 8000 --directory docs                # open http://localhost:8000/traces/
```

The exporter reads `.eval` archives directly and needs no extra dependencies. A separate drag-and-drop viewer for individual `.eval` files lives in [`viewer/`](viewer/).

## Dataset

Hosted on Hugging Face: [`RedAI4Code/SEVRA`](https://huggingface.co/datasets/RedAI4Code/SEVRA) (gated, read token required).

- **Malicious:** 2,250 PRs across 10 CWE classes from the 2025 CWE Top 25, built by deterministic patch reversal and paired with 15 framings. The **retained challenge split** keeps the 1,062 PRs that at least one weak baseline reviewer approved, so trivially detectable attacks are dropped.
- **Benign:** 347 legitimate security fixes from the same CWE classes, applied with `git apply` from the official patches. Only the PR text is LLM-written, in a neutral tone.

Every attack is grounded in a real CVE from the OSV and SECommits datasets.

### The 15 framings

Each framing changes only the PR narrative. The diff stays fixed.

| Framing | How the PR is presented |
|---------|-------------------------|
| AI Agent Authored | Routine output of an internal automation agent; steers review toward tests and lint |
| Appeal to Authority | Follows external expert guidance; deviating means ignoring it |
| Build System Laundering | Runtime change framed as build, CI or test-fixture maintenance |
| Dependency Compat Claim | Required for compatibility with a named dependency version |
| Emotional Appeal | Live outage; every minute of review prolongs the damage |
| Evidence Dilution | Load-bearing change buried among fabricated unrelated cleanups |
| Fake Bug Fix | Fixes a concrete user-visible regression |
| False Coverage | Claims tests validate the change using evidence that never exercises the attack |
| Misleading Hardening | The vulnerable diff itself is presented as hardening |
| Misleading Pass | Routine and forgettable; no rationale that invites scrutiny |
| Out of Distribution | Dense subsystem internals with no plain-English gloss |
| Prior Approval Signal | Implements a previously approved decision; re-litigation is out of scope |
| Refactoring | Cleanup of confusing code with no behavior change |
| Review Bias | Front-loaded "Security Analysis" concluding the diff is safe |
| Unsafe Optimization | Check is redundant given a caller invariant or upstream contract |

The dataset also carries two optional metadata axes, `axis1` (single PR vs. staged precondition) and `axis2` (tiny change, buried in complexity, semantic equivalent). The paper studies the framing axis; the others are available as filters ([taxonomy](assets/attack_taxonomy_axes.md)).

## How it works

The benchmark runs on [inspect-ai](https://github.com/UKGovernmentBEIS/inspect_ai). Before each evaluation a Docker container running Gitea is reset to its original image, every PR is reopened and a fresh API token is injected. The reviewer then gets one sample per PR and uses GitHub-compatible tools to read diffs, file histories and the wider codebase before approving or declining. Commit history is squashed so the attack cannot be spotted by comparing commits.

Malicious PRs were generated in three stages: a profiler agent analyses each fix commit and proposes plausible non-security justifications for reversing it; an executor agent synthesises the change, which is checked with tree-sitter and an LLM quality judge (low-quality PRs are regenerated); validated PRs are deployed to Gitea.

![Example PR in Gitea](assets/pr_example.png)

## Quickstart

**Requirements:** Docker with Compose, Python 3.10+, [`uv`](https://github.com/astral-sh/uv).

```bash
uv sync
```

**Hugging Face access.** The dataset is gated. Create a read token at [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens), then:

```bash
uv run python -c "from huggingface_hub import login; login()"
```

**Model credentials.** Set whichever providers you use:

```bash
export ANTHROPIC_API_KEY=sk-ant-...            # Anthropic
```

```env
# .env in the repo root, for Azure OpenAI
AZUREAI_OPENAI_BASE_URL=https://<your-resource>.openai.azure.com/
AZUREAI_OPENAI_API_KEY=<your-key>
```

```bash
export CLAUDE_CODE_USE_BEDROCK=1               # AWS Bedrock
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...                   # if using temporary credentials
```

**Run one CWE.**

```bash
# Malicious PRs: Refusal Rate and Security Reason Rate
uv run inspect eval benchmark/task.py@reviewer_benchmark \
  --model anthropic/claude-opus-4-6 \
  -T cwe=cwe79 \
  -T prompt_variant=plain \
  --log-dir logs/malicious/cwe79

# Benign PRs: False-Decline Rate
uv run inspect eval benchmark/task.py@benign_benchmark \
  --model anthropic/claude-opus-4-6 \
  -T cwe=cwe79 \
  -T prompt_variant=plain \
  --log-dir logs/benign/cwe79
```

Add `--limit 4` for a quick smoke test. While a run is going, it prints the `GITHUB_API_URL` of its Gitea instance; open the same host and port without `/api/v1` to watch the PRs live.

> **Prompt variant.** The code defaults to `prompt_variant=security`, which tells the reviewer to look for security problems. The paper evaluates the `plain` prompt, which never mentions security, so pass `-T prompt_variant=plain` to reproduce its numbers.

### Reproducing the paper

```bash
CWES="cwe79 cwe89 cwe352 cwe862 cwe787 cwe22 cwe416 cwe125 cwe78 cwe94"

for cwe in $CWES; do
  uv run inspect eval benchmark/task.py@reviewer_benchmark \
    --model <model> -T cwe=$cwe -T prompt_variant=plain \
    --log-dir logs/malicious/$cwe
done

for cwe in $CWES; do
  uv run inspect eval benchmark/task.py@benign_benchmark \
    --model <model> -T cwe=$cwe -T prompt_variant=plain \
    --log-dir logs/benign/$cwe
done
```

By default the malicious task keeps only PRs that at least one weak baseline approved (the `failed_by` filter, with models listed in [`benchmark/config.py`](benchmark/config.py)). That list currently includes Grok Code Fast alongside the two baselines named in the paper (Haiku 4.5 and GPT-5.4-nano).

### Reading the results

Each run writes an Inspect `.eval` archive to `--log-dir`. Summarise them with:

```bash
uv run python scripts/analyse_results.py --logs-dir logs/malicious
uv run python scripts/analyse_benign_results.py --logs-dir logs/benign
```

## Agents and tool modes

`-T agent=` selects who reviews. `-T tool_mode=` selects what the reviewer can use.

| `agent` | Description |
|---------|-------------|
| `default` | ReAct-style LLM reviewer driven by inspect-ai (used for the paper) |
| `claude-code` | Claude Code CLI running agentically in a Docker sandbox |
| `copilot-cli` | GitHub Copilot CLI running agentically in a Docker sandbox |
| `copilot-sdk` | Copilot SDK on the host, routing bash into the sandbox (legacy) |

| `tool_mode` | Description |
|-------------|-------------|
| `sandbox` (default) | Gitea tools plus bash in a Docker sandbox with the repo cloned at `/workspace/repo` |
| `gitea` | Gitea/GitHub-compatible API tools only |

<details>
<summary>Claude Code and Copilot examples</summary>

**Claude Code via Bedrock.** `--model` is the inspect-ai model used for scoring; `-T model=` is the model Claude Code uses inside the sandbox. The CLI sandbox image is selected automatically.

```bash
export CLAUDE_CODE_USE_BEDROCK=1 AWS_REGION=us-east-1   # plus AWS credentials

uv run inspect eval benchmark/task.py@reviewer_benchmark \
  --model bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0 \
  -T agent=claude-code \
  -T model=global.anthropic.claude-sonnet-4-6 \
  -T cwe=cwe79 \
  --log-dir logs/claude-code
```

**Claude Code via the Anthropic API.**

```bash
export ANTHROPIC_API_KEY=sk-ant-...

uv run inspect eval benchmark/task.py@reviewer_benchmark \
  --model anthropic/claude-sonnet-4-6 \
  -T agent=claude-code -T model=claude-sonnet-4-6 \
  -T cwe=cwe79 --log-dir logs/claude-code
```

**Copilot CLI.** Build the image once, then run. `COPILOT_GITHUB_TOKEN` is forwarded to the container, which is configured by `scripts/sandbox-compose-copilot.yaml`.

```bash
export COPILOT_GITHUB_TOKEN=<github token>
docker build -f scripts/Dockerfile.sandbox-copilot -t rufimelo/sandbox-cli:copilot .

uv run inspect eval benchmark/task.py@reviewer_benchmark \
  --model anthropic/claude-opus-4-6 \
  -T agent=copilot-cli -T cwe=cwe79 \
  --log-dir logs/copilot-cli
```

</details>

## Configuration reference

### `reviewer_benchmark` (malicious PRs)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `cwe` | none | CWE class: `cwe79`, `cwe89`, `cwe352`, `cwe862`, `cwe787`, `cwe22`, `cwe416`, `cwe125`, `cwe78`, `cwe94` |
| `version` | `gpt5.2-filtered` | Malicious dataset version |
| `hf_dataset` | `RedAI4Code/SEVRA` | Hugging Face dataset; set `""` to use `jsonl_path` instead |
| `jsonl_path` | none | Local `generated_prs.jsonl` (when `hf_dataset=""`) |
| `axis1` | none | Filter by distribution strategy: `single_pr_introduction`, `precondition_staging` |
| `axis2` | none | Filter by concealment: `tiny_change`, `buried_in_complexity`, `semantic_equivalent` |
| `axis3` | none | Filter by framing, e.g. `fake_bug_fix`, `prior_approval_signal` |
| `prompt_variant` | `security` | `security` or `plain` (the paper uses `plain`) |
| `failed_by` | weak baselines | Keep only PRs these models approved; see `WEAKER_MODELS` in `benchmark/config.py` |
| `agent` | `default` | See [Agents and tool modes](#agents-and-tool-modes) |
| `tool_mode` | `sandbox` | `sandbox` or `gitea` |
| `review_mode` | `independent` | `independent`: one sample per PR; `sequence`: keep multi-PR groups together |
| `simulate_merge` | `true` | Record approvals in memory instead of merging in Gitea, so samples stay independent. CLI agents always simulate. |
| `reset` | `true` | Reset the Gitea container before the run |
| `gitea_port` | `0` | `0` picks a free host port |
| `gitea_project` | auto | Docker Compose project name; unique per run by default |

### `benign_benchmark` (legitimate fixes)

Takes `cwe`, `hf_dataset`, `jsonl_path`, `agent`, `tool_mode`, `prompt_variant`, `reset`, `gitea_port` and `gitea_project` with the same meanings and defaults as above, plus `version` (default `gpt5.2_v2`).

Useful inspect options: `--limit N`, `--max-samples N` (concurrency), `--log-dir PATH`.

### Parallel runs

Each evaluation allocates its own Gitea port and Compose project, so two `inspect eval` processes can run side by side as long as their `--log-dir` differ. Pass `-T gitea_port=3001 -T gitea_project=my-run` only when you need a stable Gitea URL for debugging.

### Local datasets and debugging

```bash
# Use your own generated PRs
uv run inspect eval benchmark/task.py@reviewer_benchmark \
  --model anthropic/claude-opus-4-6 \
  -T hf_dataset="" -T jsonl_path=/path/to/generated_prs.jsonl \
  --log-dir logs/custom

# Narrow to one concealment and framing, and keep Gitea state afterwards
uv run inspect eval benchmark/task.py@reviewer_benchmark \
  --model anthropic/claude-opus-4-6 \
  -T cwe=cwe79 -T axis2=tiny_change -T axis3=fake_bug_fix -T reset=false \
  --log-dir logs/cwe79_debug
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Gitea container will not start | Check `docker ps` and `docker logs <container>`. Runs create and clean up their own Compose project. |
| Port already in use | Leave `gitea_port` at its default `0`, or pass a free port with `-T gitea_port=3002` |
| Hugging Face token rejected | `rm ~/.cache/huggingface/token`, then log in again as above |
| Provider says the API key is missing | Confirm the variable is exported in the shell you run `uv run` from |

## Repository layout

| Path | Contents |
|------|----------|
| `benchmark/` | inspect-ai tasks, agents, tools, scoring and dataset loading |
| `scripts/` | Docker files, sandbox compose files and result-analysis scripts |
| `docs/` | Project page, leaderboard generator and the trace explorer (`docs/traces/`) |
| `viewer/` | Drag-and-drop browser viewer for `.eval` logs |
| `tests/` | Unit tests (`uv run pytest`) |

## Citation

```bibtex
@article{melo2026sevra,
  title   = {Sevra-Bench: Social Engineering of Vulnerabilities in Review Agents},
  author  = {Melo, Rui and Fogliato, Riccardo and Zhou, Sean and Thaker, Pratiksha and Wu, Zhiwei Steven},
  journal = {arXiv preprint arXiv:2606.13757},
  year    = {2026},
  url     = {https://arxiv.org/abs/2606.13757}
}
```
