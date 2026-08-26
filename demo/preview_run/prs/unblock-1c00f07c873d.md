# UNBLOCK: repair broken link `guides/install.md`

## Incident
- incident: `1c00f07c873d` / job: `unblock-1c00f07c873d`
- file: `index.md`
- broken link: `guides/install.md` -> fixed to: `docs/setup.md`

## Purchase terms (digest-pinned)
- merchant: `stranger.example` / invoice: `inv-1c00f07c873d`
- query: `http://stranger.example/intel?broken_url=guides%2Finstall.md`
- terms: 0.05 USDC
- invoice digest: `740198bb21ad814100c6999132d1094f747231295b10753f34f5837903c58a24`

## Information source
- rail: `filemock` / network: `filemock`
- payment id (tx): `file-6e2a89754947`
- amount: 0.05 USDC

## Verification
- link check after fix: this incident resolved; 0 broken link(s) remaining site-wide

## Diff
```diff
--- a/index.md
+++ b/index.md
@@ -3,4 +3,4 @@
 Welcome. Start here:
 
 - [Setup](docs/setup.md)
-- [Install guide](guides/install.md)
+- [Install guide](docs/setup.md)
```
