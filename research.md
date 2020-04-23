## signature

### PGP / GPG

#### problems with pgp

https://latacora.micro.blog/2019/07/16/the-pgp-problem.html

### other tools

#### signify

- https://www.openbsd.org/papers/bsdcan-signify.html
- http://man.openbsd.org/OpenBSD-current/man1/signify.1
- openbsd signing tool
- sign verify file list
- attach untrusted comment
- signify -S -s signify.sec -m go.mod
- signify -V -p signify.pub -m go.mod

#### minisign

- https://jedisct1.github.io/minisign/
- compatible with signify
- attach trusted / untrusted comment
- need to know signing identity beforehand
- minisign -S -s minisign.sec -m go.mod
- minisign -V -p minisign.pub -m go.mod

### openssh (ssh-keygen -Y)

- http://man7.org/linux/man-pages/man1/ssh-keygen.1.html
- uses stdin/stdout
- namespaces must match, identity must match
- ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n file < go.mod
- ssh-keygen -Y verify -f ~/.ssh/known_signers -I arccy@eevee -n file -s go.mod.sig < go.mod
