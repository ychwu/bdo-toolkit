# Changelog

All notable released changes to `bdo-toolkit` are documented here.

## [Unreleased]

## [1.0.0] - 2026-08-30

The first stable release of `bdo-toolkit` establishes a passive, read-only
Python and CLI toolkit for live or recorded Black Desert telemetry. Validation
currently covers the NA/EU service. Item State and Arena of Solare remain
explicitly experimental APIs inside the stable package.

### Upgrade notes for pre-release consumers

- Item-event and item-state decoding now requires an explicit local
  `opcode_profile`; CLI `replay` and `live` commands require `--profile`.
  Profiles are never bundled, fetched implicitly, or merged across eras.
- Item-state serialization uses schema version 5. Consumers must use
  `storages`, `SnapshotItem.observed_at`, the `StorageContents` query surface,
  and opt-in typed diagnostics instead of removed schema-4 aliases.
- Storage events use `event_type` as the live/snapshot/unresolved discriminator,
  `source` as semantic origin, `storage_id` as authoritative destination, and
  `quantity` as the sole amount. The former storage-operation, deposit-origin,
  and quantity aliases and filters are removed.
- Raw context `0x3e010000` is labeled `Remote Inventory`; exact-source filters
  using `Magnus Remote Inventory` must be updated.
- Completed calibration results expose retention accounting only through the
  required `CalibrationResult.retention` object.
- Solare snapshot evidence is owned by `SolareCaptureResult.evidence`; it is no
  longer duplicated on `SolareLeaderboardSnapshot`.
- Direct `ProfileFetchResult` construction no longer accepts stored `path` or
  `profile_sha256` fields. Its read-only `path` derives from the installed
  profile.

### Added

- Introduce the first stable release with packet capture and PCAP replay,
  structured item and storage events, synchronous and asynchronous sessions,
  calibration and profile tooling, typed metadata, CLI workflows, experimental
  item-state snapshots, and experimental Arena of Solare snapshots.
- Add explicit verified HTTPS profile installation through
  `fetch_opcode_profile()` and `bdo-toolkit profile fetch`, with bounded
  schema-1 envelope validation, SHA-256 integrity verification, and atomic
  caller-owned installation.
- Register Angavu Outpost storage while keeping numeric `storage_id` as the
  authoritative endpoint identity.
- Add `CaptureEndpoint.to_dict()` and share its representation with the frozen
  `SolareCaptureEndpoint` subclass.

### Changed

- Require explicit opcode profiles and remove the packaged default profile.
- Compact the item-state result contract around schema version 5, canonical
  inventory and storage summaries, coverage, provenance, warnings, decoder
  health, and optional typed diagnostics.
- Make storage source, endpoint, event type, and quantity fields canonical.
- Canonicalize calibration retention under `CalibrationResult.retention`.
- Make Solare capture results the sole owner of classification evidence.
- Simplify fetched profile results while preserving verified installation.
- Rename the remote-inventory source label to `Remote Inventory`.
- Share capture endpoint serialization and the capture-health loss predicate
  across item and Solare acquisition.
- Mark the Arena of Solare domain public and experimental within the stable
  package; its Python and serialized contracts may still change before domain
  promotion.

### Fixed

- Keep live health sampling independent of packet decoding to prevent lock
  inversion and deadlock during active delivery.
- Preserve worker-deposit attribution through bounded interleaved storage
  traffic while failing closed on contested or ambiguous ownership.
- Correct Solare leaderboard guidance to capture the first load after a game
  restart rather than relying on cached refresh behavior.
- Refuse incomplete automatic transfer profiles unless manual-decrement
  evidence is present, before any profile backup or replacement occurs.
- Prevent Python 3.10 async Solare shutdown polling from busy-spinning on the
  coarse Windows monotonic clock.

### Documentation

- Publish the reference-first documentation site and promote it as the
  canonical API reference with task-first navigation, stable deep links,
  searchable public symbols, and responsive calibration walkthroughs.
- Rework the repository README into a concise stable-package entry point with
  current capabilities, installation, examples, support, and documentation
  routes.
- Make the Quickstart and example catalog live-first and task-oriented across
  item activity, item state, calibration, asyncio, and Solare.
- Add game-context orientation and clarify item-event meanings, source labels,
  storage iteration, item-state acquisition, output, acceptance checks, and
  advanced diagnostics.
- Reconcile all profile and calibration guidance around explicit local
  authority, local patch-day calibration, verified optional fetching, schema-1
  validation, controlled transfer evidence, and loot-preview limitations.
- Document NA/EU as the validated service region and treat other regions as
  unverified.
- Consolidate callback, health, lifecycle, profile-verification, Solare-load,
  and troubleshooting guidance into their owning reference pages.
- Retire stale site-draft ledgers while preserving the retained redesign file
  only as a local historical source snapshot.

### Removed

- Remove local protocol-research helpers and private-fixture baseline tooling
  from repository tracking; maintainer-local copies remain ignored and no
  private capture evidence is published.

### Tests

- Refocus the test suite on current public contracts, distinct protocol
  geometries, lifecycle failures, concurrency boundaries, cross-patch behavior,
  and reviewed private-fixture regressions.
- Normalize test source formatting without changing coverage.

### Internal

- Establish the local changeset, changelog, version-source, and release
  governance workflow used to prepare this release.
- Add guarded PyPI Trusted Publishing for version-matched tags on `main`, with
  separate unprivileged build validation and OIDC-enabled publication jobs.
- Modernize MIT license metadata and the Setuptools build requirement for
  warning-free wheel and source-distribution builds.
- Clean generated caches and local scaffolding without changing package
  behavior.
