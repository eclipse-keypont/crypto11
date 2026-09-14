# internal/pool

Resource-pool and atomic helpers used by crypto11's session pool.

## Provenance

This code was originally vendored from
[`github.com/thales-e-security/pool`](https://github.com/thales-e-security/pool)
(v0.0.2, last updated 2020-09-10), which was itself a de-vendored extract of a
few packages from [vitess](https://github.com/vitessio/vitess)
(`go/pools`, `go/sync2`, `go/timer`), trimmed to remove vitess's heavyweight
internal dependencies.

It has been copied in-tree so crypto11 owns and maintains it directly rather
than depending on an unmaintained external module. The upstream `thales-e-security/pool`
module has seen no changes since 2020, and the corresponding vitess code has since
diverged substantially (the `sync2` atomic/semaphore packages were removed in favour
of Go's native `sync/atomic`, and `go/pools` was rewritten to depend on vitess-internal
packages).

## License

This code is licensed under Apache-2.0 (see [LICENSE](LICENSE)), separate from
crypto11's MIT license. The original copyright is held by Google Inc. / The Vitess
Authors; per-file headers are preserved.
