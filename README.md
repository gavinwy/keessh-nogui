# keessh-nogui
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11115/badge)](https://www.bestpractices.dev/projects/11115)
## Intro
Provides a command line only tool for Unix-like systems to load SSH keys stored in
[KeePass](https://keepass.info/) Database  files into an SSH agent. This might be useful for
people who store SSH keys with the KeeAgent plugin for [Keepass](https://keepass.info/) or
[KeePassXC](https://keepassxc.org/) and want to use those keys in an environment that can't run
KeePass or KeePassXC, such as without a GUI.

This is a personal project for my own learning, and it's the first thing I've written in Rust, so
bear that in mind before relying on it. It's still very much a work in progress.

## License
Copyright 2025 Gavin Weifert-Yeh \
All code I've written is licensed under your choice of
[The Apache License, Version 2.0](https://spdx.org/licenses/Apache-2.0.html), or
[The BSD 2-Clause "Simplified" License](https://spdx.org/licenses/BSD-2-Clause.html), or
[The ISC License](https://spdx.org/licenses/ISC.html), or
[The MIT License](https://spdx.org/licenses/MIT.html).

All code from other sources is licensed under their respective license, including
[keepass-rs](https://crates.io/crates/keepass), which had to be embedded to add a patch.