# Documentation

The documentation is organized by purpose. Each document has one job and one
audience.

## Tutorial — start here

- [`tutorial/getting-started.md`](tutorial/getting-started.md) — build a port and
  run the first scan.

## How-to guides — accomplish a task

- [`how-to/integrate.md`](how-to/integrate.md) — wire the engine into a service as
  the inline sanitization layer.
- [`how-to/deploy.md`](how-to/deploy.md) — package and deploy the runtime.
- [`how-to/operate.md`](how-to/operate.md) — run the `serve` gateway and its
  endpoints.
- [`how-to/build.md`](how-to/build.md) — build the Lean tiers and the staged
  cache pipeline.

## Reference — look up a fact

- [`../ports/DETECTOR_COVERAGE.md`](../ports/DETECTOR_COVERAGE.md) — the twenty-seven
  detectors, the verdict shape, per-port build and run, and the coverage matrix.
- [`reference/ports.md`](reference/ports.md) — the cross-port runtime, verdict,
  reason-code, and fixture contract.
- [`reference/cli.md`](reference/cli.md) — the command-line interface, profiles,
  and modes.
- [`reference/build-tiers.md`](reference/build-tiers.md) — build tiers with memory
  and time budgets.

## Explanation — understand the design

- [`explanation/architecture.md`](explanation/architecture.md) — the three layers
  and the deployment model.
- [`explanation/threat-model.md`](explanation/threat-model.md) — the adversarial
  model the detectors defend against.
- [`explanation/tcb.md`](explanation/tcb.md) — the trusted computing base and the
  assurance argument.

## Roadmap and history

- [`ROADMAP.md`](ROADMAP.md) — forward-looking work only.
- [`../CHANGELOG.md`](../CHANGELOG.md) — release history.
