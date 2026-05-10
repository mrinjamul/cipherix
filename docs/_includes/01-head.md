# cipherix

[![build status](https://github.com/mrinjamul/cipherix/workflows/test/badge.svg)](https://github.com/mrinjamul/cipherix/actions)
[![release status](https://github.com/mrinjamul/cipherix/workflows/release/badge.svg)](https://github.com/mrinjamul/cipherix/actions)
[![go version](https://img.shields.io/github/go-mod/go-version/mrinjamul/cipherix.svg)](https://github.com/mrinjamul/cipherix)
[![GoReportCard](https://goreportcard.com/badge/github.com/mrinjamul/cipherix)](https://goreportcard.com/report/github.com/mrinjamul/cipherix)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/mrinjamul/cipherix/blob/master/LICENSE)
[![Github all releases](https://img.shields.io/github/downloads/mrinjamul/cipherix/total.svg)](https://GitHub.com/mrinjamul/cipherix/releases/)

A command-line file encryption tool written in Go. Supports **AES-256-GCM**, **XChaCha20-Poly1305**, and **X25519 public-key encryption** with a unified 64 KiB chunked AEAD format. Includes a built-in keystore for managing encryption keys, shell completion, and a streaming tar library for directory encryption.
