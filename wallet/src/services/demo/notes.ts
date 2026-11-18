// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The demo's Markdown files. Kept as strings rather than `.md` assets because
 * Metro does not bundle `.md` by default, and adding it to the asset list for
 * every build only to serve the demo would change the production config.
 * Invented content throughout.
 */

export const DEMO_NOTES = {
    weekendPlans: `# Weekend plans

Saturday is the **harbour clean-up**, then lunch at the quay.

## Saturday

- 9:00 meet at the slipway, gloves and bags provided
- 12:30 lunch at *The Lantern*, table for six
- 15:00 sailing club open afternoon

## Sunday

1. Coastal path from Portbridge to Hollow Cove (about 7 km)
2. Tea at the lighthouse café
3. Bus back at 16:10

> Bring a waterproof. The forecast says showers after two.

| Who    | Bringing          |
| ------ | ----------------- |
| Jordan | Flask and snacks  |
| Alex   | First aid kit     |
| Sam    | Tide timetable    |
`,
    harbourWalk: `# Harbour walk notes

A short loop for a slow morning: about **3 km**, flat all the way.

- Start at the old customs house
- Follow the wall to the lifeboat station
- Back through the market square

The bakery on Quay Street opens at 7:30.
`,
    checklist: `# Passport renewal checklist

- [x] Photo taken
- [x] Countersignatory asked
- [ ] Form checked twice
- [ ] Fee paid online

Renewal takes about three weeks. Book travel after the new one arrives.
`,
    raceSchedule: `# Autumn race schedule

| Date        | Race              | Start |
| ----------- | ----------------- | ----- |
| 1 November  | Harbour sprint    | 10:00 |
| 15 November | Lighthouse loop   | 09:30 |
| 29 November | End of season cup | 11:00 |

Briefing in the clubhouse 45 minutes before each start.
`,
};
