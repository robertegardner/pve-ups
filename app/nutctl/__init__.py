"""nutctl: config control plane for a NUT fleet.

Everything in this package renders from a single hand-edited topology file
(see :mod:`app.nutctl.topology`) — the topology is the source of truth, and
every other artifact (NUT config, per-host shutdown timers, docs) is a
deterministic render of it.
"""
