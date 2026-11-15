# Exposure console: visual design

Status: outline. To be filled in during phase 2, when the console is built against mocked data.

What the console shows and lets the admin do is in [exposure-design.md](exposure-design.md#console). This file records how it looks: the decisions a developer would otherwise make one screen at a time. Mockups and prototypes are linked from here, not drawn here.

This file covers only the console, so it moves to the console's repository once there is one.

## Base look

Decided: the console has its own styling and theme, and does not reuse the scanner frontend's.

To decide:

- Component library, or none.
- Typography, spacing scale and colour tokens.

## Status presentation

One label and colour per lifecycle status, used everywhere a status appears: the queue, the history, the workspace header.

| Status | Label | Colour |
|---|---|---|
| `grouping` | | |
| `planning` | | |
| `awaiting_confirmation` | | |
| `deploying` | | |
| `deployed` | | |
| `failed` | | |
| `cancelling` | | |
| `cancelled` | | |
| `superseded` | | |

Also to decide: how the queue marks an exposure that something blocks from planning.

## Plan review

The screen the admin approves from, so it needs the most attention. To decide:

- How the AS3 declaration is shown: collapsible sections, syntax highlighting, copy.
- How the dry-run diff is shown: side by side or unified.
- How each VIP's IP, DNS names, certificate and services are laid out, with each service's original origin next to the URL that replaces it.
- How the app's rewrite map is shown, with the `published` services' entries told apart from the new ones.
- Where the warnings sit relative to the confirm button.

## Grouping

To decide:

- How services move between groups: drag and drop, or select and move.
- How validation errors and warnings show on each service.
- How the read-only services, `published` and excluded, are set apart from the ones being grouped.
- How the workspace shows that another admin saved the grouping while this one has unsaved changes.

## Progress and failure

To decide:

- How the agent's steps appear as they arrive, while `planning`, `deploying` and `cancelling`.
- How a failed step, its message and the step log are shown.

## Destructive actions

Confirm deploys to the F5; cancel releases IP reservations, certificates and DNS records. To decide:

- How these buttons are set apart from the rest.
- What their dialogs show: for confirm, the plan's summary; for cancel and retry, the lists described under Console in the design doc.

## Density, dark mode, accessibility

To decide:

- Density, given the admins' screens and how many services an exposure can hold.
- Whether there is a dark mode.
- Accessibility target, keyboard use of the grouping screen, and status colours that are not the only cue.

## Mockups

None yet.
