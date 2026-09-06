# ADR-037 — The last three rows are about the deployment

- Status: accepted
- Date: 2026-09-06
- Milestone: 6 (Chunk 30); closes T-5.1, T-5.5 and T-5.6, the last `partial` rows of
  [`THREAT_MODEL.md`](../../THREAT_MODEL.md) §6. **The matrix is now thirty-six `test` rows and
  no `partial`**, which is the M6 acceptance criterion. Re-opens and settles decision F-5

## Context

Chunk 27's matrix found eight mitigations the model asserted and the code did not have. Chunks 28
and 29 closed five by writing code. The three left over had something in common that only became
visible once the others were gone: none of them is about what the application does. They are about
how it is packaged, what it is built from, and whether an isolated network is really isolated.

That is also why they were the ones left. A test that reads a Python function is cheap; a claim
about a container's root filesystem can only be settled by starting the container.

## Decision

### T-5.1 — read-only root filesystems, from measurement rather than from a list

Every service in `docker-compose.yml` sets `read_only: true` through the shared hardening anchor,
with sized `tmpfs` mounts for exactly what each one writes.

**The writable paths were measured.** `docker diff` against a stack that had been up for seven
hours said: `db` writes its socket and lock file and nothing else; `api`, `worker` and `scheduler`
write only dramatiq's Prometheus directory under `/tmp`; and `redis` and `web` write **nothing at
all**. Guessing would have produced a longer list and a false sense of having thought about it.

That measurement immediately paid for itself. `/app/samples` **does not exist in the api image** —
Docker was creating the bind-mount destination at container start, which is a write to the
container layer and precisely what `read_only` forbids. Both that and the web cache directory are
now created in their Dockerfiles. A compose-only change would have shipped and broken the stack.

**It was verified by running it, not by reading it.** The stack was rebuilt from current code and
started: six healthy containers, `ReadonlyRootfs: true` on every one, `touch /app/probe` refused,
`make migrate` succeeded, a **1.9 MB multipart upload accepted** — the Starlette >1 MiB disk
rollover into the api's tmpfs, which is the one clause no unit test can reach — the whole ingest
and detection pipeline completing, and `docker diff` afterwards reporting zero rootfs writes.

Each `tmpfs` carries a size, because a tmpfs is RAM and an unbounded one turns a write path into a
way to exhaust the host. The api's is asserted to be at least `INGEST_MAX_BODY_BYTES`, read from
the settings rather than repeated, so an upload can only ever be refused by the documented cap and
not by the mount underneath it.

`read_only` is deliberately **not** applied to the test runner or the lab, and the test says why
rather than leaving it as an omission: the test runner's whole job is to write into a bind-mounted
checkout, and the lab's sensor writes a pid file and its own capture.

### T-5.1's other half — F-5 re-opened, and kept

Digest pinning is the clause this chunk decided *not* to write, which needs more justification
than writing it would have.

Pinning by digest buys reproducibility and resistance to a tampered upstream tag. It also freezes
the image. **Nothing in this repository bumps a digest** — there is no `dependabot.yml` at all, so
the Dependabot that `docs/STATUS.md` mentions is alerts, not version updates. Pinning without an
updater, on a project with one maintainer, means the images stop receiving security patches and
nobody notices until a scan says so. That is a worse position than the one F-5 chose.

So F-5 stands, and the compensating control is the thing this same chunk adds: the image scan
reads what is actually inside every image, on every push and weekly, so a tag that moves to
something *vulnerable* is reported. Written down as **R-10**, including the part it does not
cover — a tag that moves to something malicious but free of known CVEs is exactly what digest
pinning would have caught and this does not.

The lab's Suricata sensor stays pinned by digest. It is third-party, it is pointed at hostile
traffic, and it has no reason to float.

### T-5.6 — a scan that reads the image, and fails

`pip-audit` and `pnpm audit` read lockfiles. A CVE in the base distribution's openssl ships inside
every container this project builds and appears in neither. The `images` job builds what the stack
builds and scans it with Trivy, alongside the two images the stack pulls rather than builds.

Three choices, each with a reason:

- **It fails the job; it does not upload SARIF.** Code scanning is not enabled on this repository —
  the API answers `403` — so a SARIF upload would go nowhere and the finding would be lost. A
  report nobody can read is not a control.
- **It ignores unfixed findings.** A base image carrying a CVE with no upstream fix would otherwise
  turn every push red until somebody invented a fix that does not exist. A gate nobody can pass is
  a gate people learn to switch off. This is a deliberate weakening and it is written down so that
  reversing it is a decision rather than an edit.
- **Two builds cover four services.** `api`, `worker` and `scheduler` share a build context and
  target, so they are one image under three names. A test asserts that rather than leaving it as
  something somebody once noticed — and the same test fails if a service is added whose image
  nothing scans, or if the stack swaps in a different image.

The lockfile audits stay. Trivy reads what is installed in the image; `pip-audit --strict` reads
the resolved lockfile including packages a build stage discards. Neither contains the other.

### T-5.5 — the pre-flight is asked in CI, which is what earns the row

Every other lab assertion holds the manifests to what they *declare*. A manifest can be wrong in a
way a manifest cannot detect: `internal: true` tells Docker not to attach a default route, and it
does not stop the host-side bridge address from answering — that took
`com.docker.network.bridge.inhibit_ipv4`, and the way anyone found out was by running the
pre-flight inside a lab container and watching it fail (E-54).

Until now that ran only when an operator remembered. Moving it behind a pytest marker would have
changed nothing: it would be the same command, run by the same person, on the same schedule of
never. So it runs in CI. It is cheap enough that there was no excuse — only the lab *target* comes
up, and it builds from this project's own runtime image, so Suricata is never pulled. The job was
run locally, step for step, before being written down: internal network confirmed, `default
routes: none`, `answered … : nothing`, one attached container, clean teardown.

L-3 — the operator's attestation that the systems are theirs — is **R-11**. No test can confirm a
statement about the world outside the process, and writing a check that looks like one would be
worse than saying so.

## Consequences

- Positive: `THREAT_MODEL.md` §6 is thirty-six `test` rows and no `partial`. The M6 criterion —
  every mitigation maps to a named passing test or an accepted-risk entry — is met, and it is met
  in a form a suite checks rather than a form a reviewer takes on trust.
- Positive: three of the eight original gaps were closed by code, three by testing behaviour that
  existed but was only ever checked by hand, and two by deciding in the open that the mitigation as
  first worded was not the right one for a single-node self-hosted lab. Writing the last two down
  as R-10 and R-11 is the difference between a residual risk and an unfinished job.
- Negative: the image scan will eventually fail on a base-image CVE that has a fix, and somebody
  will have to bump a tag to clear it. That is the control working, and it is also a maintenance
  cost this project did not have yesterday.
- Negative: a read-only rootfs makes a class of debugging harder — no writing a file into a running
  container to test something. `docker-compose.override.yml` remains the escape hatch and is
  gitignored, so it never ships.
- Neutral: the `lab` CI job adds about a minute to every push, for a check that has failed exactly
  once in this project's history — which is one more time than most checks that get deleted for
  being slow.
