# preview fixtures

`preview_site/` and `preview_intel.json` belong to the owner preview only. The
Gate C demo keeps using `site/` and `intel_db.json`; nothing here changes what
that demo proved.

They exist because the preview tells a different story - a package nobody has
reviewed turned up in a release build - and the story has to be what the code
actually did. Re-skinning the copy over the link-repair fixture would have put
"unknown dependency" on the left while the panel on the right showed
`guides/install.md`: the same contradiction as the price mismatch and the
panel-ahead-of-the-story bugs.

The pipeline is unchanged. It finds a reference that does not resolve - here a
review card that does not exist, because nobody has reviewed that version -
buys the record naming what to use instead, rewrites the one allowlisted file
and verifies. `release.md` also cites a package that IS reviewed, so the diff
has an untouched neighbour to be measured against.

The link labels carry no version number on purpose. The pipeline rewrites a
link's target, not its text - correct for a link fixer - so a label reading
"quickparse 0.4.1" would have survived beside a target of 0.4.3 and the diff
would have shown a line contradicting itself.
