# Where the chip is

To verify an identity, the Privasys Wallet reads the chip in a passport or ID
card over NFC. The holder has to lay their phone on the right part of the
document, and that part differs from one country to the next, and from one
design to the next within a country: the back cover, the front cover, the photo
page, a plastic page of its own.

## Why this list has to be built

Where the chip sits was never part of what makes passports work together. The
standard they follow (ICAO Doc 9303) says what the chip holds and how to talk to
it, and leaves its place in the booklet to the issuer. It did not need to say
more: a border gate or a desk reader lays the whole open booklet on an antenna
the size of the page, which powers the chip wherever it is and whichever way up
the booklet lies.

A phone is a different reader. Its antenna is small, sits in one spot, and
reaches a few centimetres. Placement only became a problem once people began
reading their own passports with their phones, at home, with nobody to show them
how. So no public list exists, because until then nobody needed one.

This folder is one. It is open so that anyone who knows where a document's chip
is, and can point to a page that says so, can add it.

## The one rule

**Every entry names a page that states it, and quotes the sentence.**

Not "my passport reads from the back": a closed passport is thin enough to read
from either side, so that shows the chip can be reached, not where it is. Not an
answer from an AI assistant either, however confident: we have had those quote
real documents that turned out to describe something else. A page a reviewer can
open, and the words on it.

A document with no entry is not a problem. The wallet then asks the holder to
try the back cover, the photo page and the front cover in turn, which always
finds the chip. A wrong entry is worse than a missing one.

## What is here

| | |
|---|---|
| `countries/` | One file per issuing state. This is what you edit. |
| `build.cjs` | Builds the list the wallet reads from `countries/`. |
| `validate.cjs` | The checks, run by the build, the tests and the deploy. |
| `sign.cjs` | Signs the built list for publishing. Maintainers only. |

The built list is `wallet/src/services/chip-placement.data.json`. It holds the
bare rules and none of the evidence, is compiled into the app, and is served,
signed, at `https://privasys.id/wallet/chip-placement.json`, so a wallet that is
already installed picks up a new entry without an update.

## Adding or correcting an entry

1. Find the file for the country in `countries/`, or create it. The file is
   named after the country's ISO 3166-1 alpha-3 code: `GBR.json`, `DEU.json`.
2. Add a rule (see below).
3. Run `node chip-placement/build.cjs`. It checks your file and rebuilds the
   list. Commit both.
4. Open a pull request. See [CONTRIBUTING.md](../CONTRIBUTING.md).

```json
{
  "country": "GBR",
  "name": "United Kingdom",
  "rules": [
    {
      "document": "passport",
      "series": "Series C, dark blue cover",
      "issuedFrom": "2020-01",
      "issuedTo": "2025-11",
      "positions": ["photo-page"],
      "evidence": "documented",
      "source": "https://www.gov.uk/government/publications/basic-passport-checks/basic-passport-checks-accessible",
      "sourceType": "government",
      "quote": "The electronic chip is embedded within this page.",
      "checked": "2026-11-12",
      "note": "Series D, from December 2025, is not covered: the source does not state its chip position."
    }
  ]
}
```

| Field | |
|---|---|
| `document` | `passport` or `id-card`. |
| `series` | The design, in words a holder or a reviewer would recognise. Optional. |
| `issuedFrom`, `issuedTo` | First and last month of issue the rule holds for, `YYYY-MM`. Leave out an end that is open. Give them whenever the source does: a rule with no dates applies to every document of that state. |
| `positions` | Where to try, in order. One or more of the positions below. |
| `evidence` | `documented` or `inferred` (below). |
| `source` | The page, `https`. A page anyone can open, not a search result or a login. |
| `sourceType` | `government` (the issuer, its ministry or agency), `printer` (who makes the document), `trade` (a specialist publication), `vendor` (an identity-verification company's guidance). |
| `quote` | The sentence on that page that says so, word for word, in its own language. |
| `checked` | The day you read the page, `YYYY-MM-DD`. |
| `note` | What the source does not say, and anything a reviewer should know. Optional. |
| `country`, `name` (per file) | The ISO 3166-1 alpha-3 code, matching the file name, and the country in plain words. |
| `validity` (per file) | Only for a state whose passports are **not** valid for 10 years (adult) and 5 (child): `{ "adult": 5, "child": 5 }`. Leave it out otherwise. See "How the wallet uses it" for why it matters. |

### Positions

| | |
|---|---|
| `back-cover` | In the back cover. Scanned with the document closed. |
| `front-cover` | In the front cover. Scanned with the document closed. |
| `photo-page` | In the page with the photo and personal details, usually a stiff plastic one. |
| `chip-page` | In a stiff page of its own inside the booklet, which is not the photo page. |
| `inside-back-cover`, `inside-front-cover` | In that cover, and the cover is shielded, so the booklet has to be opened and the phone laid on the inside of it. |
| `card` | An ID card. |

If the source says "the cover" without saying which, give both, back first, and
say so in `note`.

Shielding is a position and not a yes/no field on purpose. A wallet that does
not know a position drops the rule and falls back to trying each place; a field
it did not know would be ignored, and the holder told to scan a closed cover
that blocks the signal.

### Evidence

- **`documented`**: the source states where the chip is. The wallet tells the
  holder so.
- **`inferred`**: the source states something the position is deduced from,
  typically that the data page is polycarbonate, where the chip is usually
  laminated in. That is a good guess and not a fact: some passports with such a
  page carry the chip in a cover or in a separate page. These go to a separate
  part of the built list (`suggestions`), which a wallet shows as a place to
  try first once it has the wording for it.

Prefer a government or printer source. A vendor's page is accepted when it is
the only one that states the position; say so in `note`.

## How the wallet uses it

The lines of code on the document give the issuing state, the expiry date and
the date of birth. They do not give the issue date, and the issue date is what
tells one design from the next: sources say "passports issued from March 2017",
never "passports expiring from". So the wallet works it out: expiry, less the
years the document is valid for, which is 10 for an adult and 5 for a child
almost everywhere. The date of birth says which of the two applies. A state
that uses other periods says so in `validity`, or its documents would be placed
in the wrong design.

Countries are ISO codes throughout, in these files and in the built list. A few
documents write something else for their issuing state in their own lines of
code (German passports write `D`); the wallet turns that into the ISO code when
it reads the document, so nothing here needs to know.

Near a change of design the estimate could fall either side, so a rule applies
when its dates reach within a year of it, and where two rules do, the holder is
given both places, the likelier first.

Whatever a rule says, the remaining places follow it. A rule that is out of
date costs the holder a moment and never the check.

## Publishing

Maintainers publish the built list with the `Deploy chip placement list`
workflow. It is signed with a key whose public half is pinned in the wallet, so
serving privasys.id is not enough to change what a wallet shows.
