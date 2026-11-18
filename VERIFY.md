# VERIFY

Checks the dev sandbox can't run. Each entry lists what it checks and why the sandbox can't, the exact commands, the expected results and the latest result. Run commands from the repository root on `staging`.

## Real-ZFS backup, restore and isolation

Checks the whole dataset path on real OpenZFS 2.4.4: libzfs_core calls, `zfs allow` delegation, the systemd hardening and socket activation of zfsd, netd and both client halves, real `zfs send` streams through the validator (including raw encrypted ones), and volmode=none (no `/dev/zvol` nodes for received zvols). The sandbox has no KVM and no ZFS kernel module, so it runs these paths only against the fake ZFS.

```sh
nix build -L .#checks.x86_64-linux.vm-backup-restore
```

Expected: exit status 0, and the log shows every subtest finishing: tree and isolation properties, first backup is full, incrementals/holds/retention, zvol source, raw send, snapshotPattern mode, list and restore, replace, server status, privilege split, wrong password, insecure client.

Latest result: not run yet.

## Power cuts and resume on real ZFS

Checks that real `receive_resume_token` state survives a server power cut and a client power cut mid-stream, that the client decodes and resumes it with `lzc_send_resume`, and that the result restores byte for byte. The sandbox can't crash a kernel holding a real pool; the fake ZFS only approximates resumable receives.

```sh
nix build -L .#checks.x86_64-linux.vm-crash-resume
```

Expected: exit status 0; subtests "server power cut mid-stream leaves resumable state", "client power cut during the resumed run", "next run resumes and completes" and "restored data matches" all finish. The third run may wait up to about two minutes for TCP keepalive to close the half-open connection the client's power cut left on the server.

Latest result: not run yet.
