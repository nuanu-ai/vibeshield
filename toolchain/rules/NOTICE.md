# Curated GitLab SAST rules

Source: https://gitlab.com/gitlab-org/security-products/sast-rules

Frozen revision: `7051ea7602a210dfb0793916afedc9a0555addb7` (v2.10.0).

The selected rule files are unmodified source under `rules/lgpl/javascript/`.
Their GNU Lesser General Public License v3.0 notices apply to those files;
the repository root MIT license does not override them. Original njsscan source
URLs and revision notices remain in each rule and in the upstream fixtures where
provided. The selected directory license and the root license are preserved as
`LICENSE-LGPL-3.0` and `LICENSE-MIT`. `LICENSE-GPL-3.0` supplies the GNU GPL v3
terms incorporated by LGPL v3; its official source URL and hash are in the manifest.

`manifest.json` records the exact upstream paths, source hashes, rule modes and
remediation keys. Fixtures are source inputs for static rule tests, never executed
as applications. No files from `rules/lgpl-cc/` are included. All selected YAML
files are self-contained; they have no local rule dependencies to resolve.

This bundle includes LGPL-covered source. Recipients can inspect and modify the
rule files under the accompanying licenses. VibeShield's service integrity check
requires the approved manifest to agree with the installed rules.
