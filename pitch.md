original idea:
from the observation you can just add data onto the end of a binary
no elf section necessary and with suitable delimiters
this can also be applied to scripts (prefix with comment chars).
this way file signatures are always available (no separate file)
and will survive most (all?) transport methods (download over http)
unlike file attributes
so it would be something like digsig/bsign

research question:

- is the above (hash/signature as suffix) a feasible solution to storing / validating signed code
  - does this work for compiled executables
  - does this work for scripts / interpreted runtimes (see link in linux ima)
  - how does this compare to existing solutions / work as an extension to existing framework

(incomplete) list of application whitelisting solutions
by platform / developer appname / date active

signed / integrity

- linux / kernel integrity measurement architecture / 2005 - present
  - hash based measurement
  - integration with TPM, measurement + attestation
  - uses filesystem extended attributes
  - possiblity of modifying interpreters to enforce ima for scripts
  - https://marc.info/?l=linux-kernel&m=111682497821375&w=2
- linux / microsoft integrity policy enforcement / 2020 - present
  - linux security module
  - hash based integrity
  - more geared for bootup process? entire filesystem based? no docs
- linux / digsig - bsign / 2002 - 2009
  - kernel module
  - enforcing signed binaries
  - hash / signature in extra ELF section
- macos / apple gatekeeper / 10.7.3 - present
  - enforce signed application
- windows / microsoft applocker / windows 7 - present
  - path, execution context, signed binary
- container / docker content trust / 2015 - present
  - signed docker container, build / execute enforcement
- cloud / google cloud binary authorization / 2018 - present
  - signed docker container, attestation, execute enforcement

path / other

- linux / redhat selinux / 2000 - present
  - linux security module
  - filesystem attribute based mandatory access control
- linux / redhat fapolicyd / 2016 - present
  - linux security module
  - path based application whitelisting
  - integration with selinux
- linux / canonical apparmor / 1998 - present
  - linux security module
  - path based mandatory access control
- windows third party application whitelisting
  - Ivanti Application Control
  - McAfee Application Control
  - Trend Micro Application Control
  - Faronics Anti-Executable
  - Kaspersky Whitelisting
  - Airlock Application Whitelisting
  - Thycotic Application Control
  - ...
