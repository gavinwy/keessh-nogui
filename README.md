# keessh-nogui
## Intro
Provides a command line only tool for Unix-like systems to load SSH keys stored in KeePass Database
files into an SSH agent. This might be useful for people who store SSH keys with the KeeAgent plugin
for Keepass or KeePassXC and want to use those keys in an environment that can't run KeePass or
KeePassXC, such as without a GUI.

This is a personal project for my own learning, and it's the first thing I've written in Rust, so
bear that in mind before relying on it. It's still very much a work in progress.

## License
Copyright 2025 Gavin Weifert-Yeh \
All code I've written is licensed under your choice of Apache License, Version 2.0,
OR The 2-Clause BSD License OR ISC License OR MIT License.

All code from other sources is licensed under their respective license, including keepass-rs, which
had to be embedded to add a patch.