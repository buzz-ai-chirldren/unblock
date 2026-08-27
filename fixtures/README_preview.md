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


## What the five fields carry here

`src/unblock/pipeline.py` accepts a paid record with **exactly** these five
fields - `set(data) != set(INTEL_FIELDS)` is a rejection - so a merchant cannot
attach anything extra to an answer the agent will act on. That is a property
worth keeping, so the threat report lives inside them rather than beside them:

| field | in this story |
|---|---|
| `broken_url` | the artefact the analysis was asked about |
| `status` | the response the sandbox saw at the destination below |
| `final_url` | where 0.4.1 was observed posting to |
| `suggested_replacement` | the version the analysis cleared |
| `observed_at` | when the sandbox ran |

Adding `verdict` or `behaviors` would make the pipeline reject the record as
invalid intel. Relaxing the field set to fit a demo narrative would trade a
real safety property for a nicer screenshot.

## Paying and refusing end somewhere different

The paid analysis clears `quickparse-0.4.3` and the feature keeps working.
Refusing leaves nobody knowing what 0.4.1 does, so the dependency is switched
off (`quickparse-quarantined.md`): the build ships, that feature does not. If
both routes ended at the same file the purchase would buy nothing and the human
decision would be theatre.
