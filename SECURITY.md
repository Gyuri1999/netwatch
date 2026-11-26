# Security policy

NetWatch is a defensive, read-only network monitor. This page explains how to report a security problem
in NetWatch itself.

## Supported versions

Only the latest release gets security fixes. The app updates itself, and each update is checked before
it is installed (see below).

## Reporting a vulnerability

Please do **not** open a public issue with the details.

1. Open the repository's **Security** tab and choose **Report a vulnerability**
   ([direct link](https://github.com/Gyuri1999/netwatch/security/advisories/new)).
   The report is private.
2. If that page is not available to you, open a normal issue that says only "I would like to report a
   security problem privately" — with no details — and wait for a reply.

Useful things to include: the NetWatch version and platform (Mac app, Windows app, Docker, Android),
what you did, what happened, and what you expected.

You can expect a first reply within a week. This is a one-person project, so fixes take as long as they
take, but confirmed problems are fixed before new features.

## What counts

In scope:
- Anything that lets a web page, a device on the network or a crafted packet run code, read files or
  change settings through NetWatch.
- Ways to make NetWatch scan or probe addresses outside private ranges.
- Secrets shown unmasked, or stored where they should not be.
- Problems in the update check.

Out of scope:
- Findings about *your own* network that NetWatch reports. Those are the product working.
- The intentionally vulnerable practice target (IoT Lab). It listens only on `127.0.0.1` and starts
  only when you ask.

## How NetWatch protects you

- The web interface listens on `127.0.0.1` by default. Requests that change something must come from
  the local page.
- Active probes go only to private address ranges. NetWatch never guesses passwords.
- SSH access uses keys only. NetWatch never asks for or stores a password.
- Updates are installed only if the release checksums carry a valid signature from a key in
  `update_signers`, the archive matches its SHA-256, and the app's identity and version match.
- Third-party files in `vendor/` are pinned to published hashes, and the page loads nothing from a CDN.

## What NetWatch sends out

NetWatch watches your traffic locally, but a few features do contact outside services, from the server side:
IP geolocation (public destination addresses are sent to ip-api.com), threat-intelligence list downloads,
the update check on GitHub, and lookups you start yourself (for example CVE or WHOIS). None of them send
packet contents, passwords or private addresses. Geolocation and reverse DNS can be switched off.
