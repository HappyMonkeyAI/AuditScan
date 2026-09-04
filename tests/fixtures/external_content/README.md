# External content fixtures

These repositories are intentionally small and are never installed, built, or executed.
Tests inspect them as bytes/text to establish the baseline for the external-content gate.

| Fixture | Purpose |
|---|---|
| `hostile_repo/` | Fake authority/instruction override text, memory-poisoning request, encoded-payload indicator, package lifecycle script, and unsafe GitHub Actions metadata. |
| `benign_threejs_repo/` | Ordinary Three.js/GLB development documentation and dependency metadata; must not trigger prompt-injection or lifecycle-script checks solely from normal prose. |

The hostile strings are test data, not operational instructions. Future scanner tests must assert provenance and policy outcomes while preserving the no-execution boundary.
