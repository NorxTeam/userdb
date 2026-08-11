# Upstream provenance

- Repository: `https://github.com/NorxTeam/userdb`
- Maintained upstream fork: `https://github.com/shadow-maint/shadow`
- Local remotes: `origin` is the Norx fork; `upstream` is the maintained
  source repository.
- Fork baseline: `e4bd855661afe7c83ad2745d086a538398205225`
  (`man: Document UAPI merging in login.defs`)
- License: preserve the upstream shadow license and notices; new Norx adapter
  code is GPL-3.0-or-later.

The upstream project remains the source of Unix account/group/password
semantics. Norx-specific code is additive under `norx/`; it does not copy host
libc behavior or silently replace upstream files. Synchronization must retain
the upstream baseline and review every conflict involving account policy.
