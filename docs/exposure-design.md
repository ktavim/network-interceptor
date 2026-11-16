# Exposure: publishing submitted apps through the F5

Status: phases 2 to 5 are built, against fake IP reservation, DNS and F5 services in the agent; see Phases.

A second frontend, for the F5 BIG-IP administrators, that takes each submitted app the rest of the way: it shows the external services the app calls that still need a VIP, lets the admin decide which services share a VIP, reserves the IP addresses, deploys the VIPs to the F5 and creates their DNS records. Browsers outside the internal network then reach the app and every service it calls through the F5, which rewrites the app's responses to point at the new names. Inside the internal network the app is unchanged.

Three parts:

| Part | Lives | Does |
|---|---|---|
| **Exposure console** (new frontend) | Internal network, published through the F5 | The queue, grouping, review and confirm, deploy progress, history |
| **Backend** (this repo) | Internal network | Owns the exposure records, validation, approval and audit; holds the work waiting for the agent |
| **Deployment agent** (new service) | Management network | The only holder of F5, IP-reservation and DNS service credentials; carries out the plans the backend approved |

## Topology

```
Management network                F5 BIG-IP                  Internal network
------------------                ---------                  ----------------
admin browser     --HTTPS-->  VIP exposure-frontend  -->  exposure console (static files)
admin browser     --HTTPS-->  VIP keycloak           -->  Keycloak
admin browser     --HTTPS-->  VIP exposure-api       -->  backend API --- PostgreSQL
deployment agent  --HTTPS-->  VIP keycloak           -->  Keycloak
deployment agent  --HTTPS-->  VIP exposure-api       -->  backend API
                                                          backend API --> Keycloak (signing keys)

deployment agent  -->  F5 management interface (AS3)
deployment agent  -->  IP reservation ("DHCP") service
deployment agent  -->  DNS service (DNS team): records and certificates
```

Every arrow points from the side that opens the connection. The internal network cannot reach the management network, and nothing here needs it to: the agent polls the backend for work and reports back on the same connection. The IP reservation and DNS services are reachable from the management network, so the agent calls them directly. The admin's browser talks only to Keycloak and the backend, never to the agent.

| Secret | Held by |
|---|---|
| F5 credentials, IP-reservation and DNS service write credentials | The agent only |
| The agent's Keycloak signing key | The agent only; Keycloak holds its public half |
| Database credentials | The backend only, as today |
| Each VIP's certificate private key | The DNS service, which generates it; the agent, which installs it; the F5 |

## Scope of an exposure

An exposure is created for every submission, in the same transaction as `POST /scans/{id}/submit`, so the queue can never miss one. It is pinned to that scan.

Its services are the scan's services with severity `cleared` that are not excluded: the F5 can publish them and no one has yet. The console shows the rest read-only for context:

- `published` services are already on the F5 and get no VIP, but the app's rewrite map still needs them (see Rewriting).
- Excluded services are out of scope.
- A submitted scan has no unexcluded `blocker` or `review` services; submit refuses them.

Kerberos services are `cleared` but not supported in v1. A browser outside the internal network cannot get a Kerberos ticket for them: it usually cannot reach a domain controller, and the ticket it would ask for names the service's new hostname, which the domain does not know. Publishing them takes APM: the F5 signs the user in another way and obtains the ticket on their behalf through constrained delegation (see Later). Until then, the backend refuses to plan an exposure that has an unexcluded Kerberos service, and the console shows the service flagged as not yet supported. The exposure waits in `grouping` rather than deploying without the service: the app's rewrite map would have no entry for it, so the app would verify cleanly and its calls to that service would still fail from outside. The severity stays `cleared`, since the F5 can publish these services and v2 will.

The same applies to an app that signs its own users in with Kerberos, but the scan records auth methods only for the services an app calls, not for the app itself, so v1 cannot detect it.

Each service already carries what its pool needs: `ips` and `port` are the pool members, and `scheme` says whether the F5 speaks HTTP or HTTPS to them. The VIP itself serves HTTPS whatever the scheme (see Grouping). Its `host` is only the name the app called it by; the VIP gets a new one (see DNS names).

The exposure also covers the app itself. Outside browsers load it through its own VIP, built from the app's `url`, which every app has: creating an app requires one, and checks that it is `http` or `https` with a host. Like every VIP it serves HTTPS, even when the app's `url` is `http://`. That VIP is where the rewriting happens. The app's first exposure creates it; later ones update its rewrite map.

Each time a plan is requested, the backend re-reads the published-origins registry. A service whose origin was registered after the scan, for example by another app's exposure, is dropped from scope as published. This is what keeps two apps that call the same backend from getting two VIPs for it.

## Lifecycle

```
grouping --> planning --> awaiting_confirmation --> deploying --> deployed
   ^            |                   |
   +------------+-------------------+  (admin changes the grouping)
```

| Status | Means | Leaves by |
|---|---|---|
| `grouping` | The admin is arranging services into VIPs | Requesting a plan |
| `planning` | Waiting for the agent to reserve IPs, render AS3 and dry-run it | The agent's result, or a change to the grouping (back to `grouping`) |
| `awaiting_confirmation` | The plan and its dry-run diff are ready for the admin | Confirm, or a change to the grouping (back to `grouping`) |
| `deploying` | Waiting for the agent to deploy, verify and create DNS records | The agent's result |
| `deployed` | Live; origins registered as published | Terminal (decommissioning comes later) |
| `failed` | A plan or deploy gave up; the agent's step log says where | Retry (back to `planning` or `deploying`, resuming), or cancel |
| `cancelling` | Waiting for the agent to release the exposure's IP reservations, certificates and DNS records | The agent's result |
| `cancelled` | The admin cancelled before deploying; everything released | Terminal |
| `superseded` | A newer submission of the app replaced it before deploying; everything not carried over released | Terminal |

Every change to the grouping increments the exposure's version, and every result from the agent names the version it was for, so a plan that finishes after the admin moved on is dropped rather than shown. The grouping is locked from confirmation on. Cancelling an exposure that holds nothing, one still in `grouping` that was never planned, goes straight to `cancelled`.

A new submission while an exposure is open supersedes it. The new exposure starts from the old one's grouping for the origins they share and takes over its IP reservations and the certificates whose names it still needs. The old one passes through `cancelling` to release what the new one did not take, and ends `superseded`. As built in phase 4, the new exposure takes over nothing yet: the old one releases everything, and the new one reserves afresh.

Two exceptions, decided during phase 4. An exposure that is `deploying` is not superseded, since a deploy cannot be stopped: it finishes beside the new one, and planning the new one is blocked until it has, when its origins are in the registry and the new one plans only what changed. One that is `cancelling` is winding down already and finishes as it is. So an app has at most one exposure in `grouping`, `planning`, `awaiting_confirmation` or `failed`. A new submission after a deploy needs no special case: the deployed origins are in the registry, so the next scan reads them as `published`. The new exposure adds VIPs only for what changed, and updates the app's rewrite map to cover every service the app now calls.

## Grouping

A VIP is one IP address and one virtual server, serving HTTPS on port 443. An LTM policy on the virtual server matches the Host header and forwards each request to the pool of the service by that name. Services on a VIP share its IP and port but keep their own pools. A service's original scheme and port appear only on its pool members: the F5 speaks plain HTTP to a member that serves HTTP and re-encrypts toward one that serves HTTPS, and the rewrite replaces the whole origin, scheme and port included.

Every VIP is HTTPS because the app's VIP is: a browser on an HTTPS page blocks its calls to `http://` URLs as mixed content, before they leave the browser. A service VIP on HTTP would deploy and verify cleanly, and the app would still never reach it from outside.

The Host header is inside the encryption, so the virtual server terminates TLS, with a certificate covering the names of every service on it. The DNS service issues it: the agent sends it the VIP's names and gets back the certificate and its private key, which the service generates (open question 2). The agent installs both on the F5 itself, and the declaration refers to them by name. The key is never in the declaration, which the backend stores and the console shows, so it never reaches the backend, the database or a browser. The F5 has to decrypt anyway, to rewrite the app's responses on its VIP and the CORS headers on the services'.

The admin puts each in-scope service into exactly one VIP group. The default proposal is one VIP per host. Since every VIP serves the same scheme on the same port, any services may share one. The backend validates every save, that each in-scope service is in exactly one group; the console only displays the errors.

## DNS names

Each VIP, the app's included, is published under new names in an external zone, such as `example.com`, through the DNS team's service, which the agent calls with each name and the IP it resolves to. The same service issues the VIPs' certificates (see Grouping). The original hostnames are never recreated anywhere, so the agent cannot collide with or repoint a name it does not own. The plan shows, for each service, its original origin and the URL that replaces it.

Every service gets its own name, formed from its original host and resolving to its VIP's IP, since the name the browser sends in the Host header is what tells a VIP's services apart. The app's VIP has one name, formed from the host of the app's `url`. A name follows from the host alone, so it stays the same across re-plans and superseding exposures, and a VIP's certificate is reissued only when the set of services on it changes. Two origins that share a host but differ in scheme or port, the app's included, would get the same name; how they are told apart is open (question 1).

## Rewriting

Inside the internal network nothing changes: users reach the app directly, and it calls its services by their original names. A browser outside reaches the app through its VIP, and the F5 rewrites the app's responses on the way out, replacing each original origin with the URL of the VIP that publishes it, so the browser calls the services through the F5 as well.

The rewrite map covers every service the app calls: the ones this exposure publishes, and the ones already `published`, whose URLs come from the registry. It lives on the app's VIP, so two apps that share a service each carry their own entry for it.

What has to be rewritten:

- Response bodies that name origins: HTML, the app's config files, its JS bundles.
- Response headers that name them: `Location`, `Content-Security-Policy` (its `connect-src` lists the original origins), cookie domains.
- The `Host` header toward a service: the browser sends the service's new name, which the VIP routes by. The VIP sets it back to the original name before forwarding, and uses the original as SNI toward an HTTPS pool member, since the service may serve several names or check which one it was called by.
- CORS: the browser sends the app's new origin in `Origin`. A service that allows only the app's internal origin rejects it, unless the service's VIP rewrites `Origin` on the way in or `Access-Control-Allow-Origin` on the way out.

What it cannot do, which the plan should flag:

- An origin the browser assembles at runtime, rather than one that appears whole in a response, is not rewritten. The interceptor sees such a call and the tracer, reading the configs and bundles, does not, so a service found by the interceptor alone is suspect.
- Bundles loaded with Subresource Integrity fail their hash once rewritten.
- A `login_redirect` service sends the browser to an identity provider with a redirect URI naming the internal origin; the provider must accept the new one too.
- Compressed responses cannot be rewritten as they are: the F5 must strip `Accept-Encoding` toward the app, or decompress first.

## Order of execution

1. **Plan** (on request, before confirmation): reserve one IP per VIP, request each VIP's certificate and key from the DNS service for the names it will serve, install them on the F5, render the AS3 declaration referring to them by name, dry-run it against the F5. Installing a certificate changes no traffic; like a reservation, it is held until the exposure deploys or releases it. The admin sees the IPs, the DNS names that will be created, the certificates, the declaration and the dry-run diff. The certificate is requested here rather than at deploy so that the declaration the admin approves is the one deployed.
2. **Confirm**: an admin approves that exact plan. Any holder of the `admin` role may confirm, including the one who arranged the grouping and requested the plan, and one approval is enough.
3. **Deploy**: dry-run again and stop if the diff differs from the approved one (the F5 drifted, or a reservation expired); otherwise post the declaration.
4. **Verify**: each virtual server is up and its pool members answer, and the app's VIP serves rewritten responses.
5. **DNS**: call the DNS service to create the records, only now, so no name ever resolves to an IP that nothing is listening on.
6. **Register**: the backend adds each origin to the published-origins registry, with the URL of the VIP that publishes it. The registry gains a column for that URL, which other apps' rewrite maps read. Entries added by hand before this have none, and must be given one before an app that calls them can be exposed.

A failure stops at that step. Retry resumes from it; cancel undoes the completed steps in reverse.

As built in phase 5:

- The agent deploys its own copy of the plan, which it keeps under the plan's hash; the backend sends only the confirmed hash. A hash the agent has no plan for fails the deploy at its first step.
- The agent's deploy steps are `recheck` (the reservations and the dry-run diff are still the plan's), `deploy`, `verify` and `dns`. Before posting, it keeps the partition's current declaration; cancelling a failed deploy deletes the DNS records it created, re-posts that declaration (or removes the partition if there was none), removes the certificates and releases the reservations, in that order. Retry skips the steps the step log has done for the version.
- Verify checks that every virtual server is available, that every pool has a member up (a member down is reported, not failed), and that a page fetched through the app's VIP, by its new name, names none of the original origins.
- AS3 declares a partition whole, so a later exposure of the same app keeps the VIPs the earlier ones deployed in its declaration, and re-renders only the app's VIP. That VIP keeps its address, certificate and DNS name, which the earlier exposure holds; the later plan creates only its services' names, so cancelling it cannot delete the app's.
- Registering marks each entry with the exposure that registered it. That exposure reads its own entries as the services it publishes, so a deployed exposure still shows them as its own. An origin someone else registered between the plan and the deploy keeps its entry; the deployment lists it as already registered.
- Registering also takes the newly published origins out of the groupings of the other open exposures (in `grouping`, `planning`, `awaiting_confirmation`, or `failed` while planning). Each one changed returns to `grouping` with a new version, dropping its plan, so no origin gets a second VIP. The app's newer exposure, blocked while this one deployed, is told it can now be planned.
- The app's VIP rewrites the app's own internal origin to its public URL as well, for the absolute links its pages make to itself. A service the app calls on that same origin would keep its own entry instead; until open question 1 is settled, such a service and the app get the same public name, and the plan fails at its first step.
- The app's own origin is registered too, at the app's public URL, so that another app that calls this one reaches it through its VIP rather than getting a VIP of its own for it. A later exposure of the app leaves that entry alone, since its app VIP is the same one.

## Console

What the console shows and lets the admin do; how it looks is in `docs/exposure-console-ui.md` in the exposure-console repository. Every rule it displays, what is in scope, what blocks a plan, what to warn about, is computed by the backend and returned with the exposure, so the console and the plan never disagree.

| Screen | Shows | The admin can |
|---|---|---|
| **Queue** | Open exposures, oldest submission first: app, submitted when and by whom, status, how many services need a VIP, whether anything blocks planning | Open one |
| **History** | Closed exposures (`deployed`, `cancelled`, `superseded`), newest first | Open one |
| **Workspace** | One exposure; its body depends on the status (below) | What the status allows |

The workspace always shows the app, its `url`, the scan the exposure is pinned to, the status and the exposure's event log: every admin action with who and when, and every step the agent reported.

| Status | Body | The admin can |
|---|---|---|
| `grouping` | The VIP groups and their services; the `published` services with their registry URLs and the excluded ones, read-only; each service's warnings; what blocks planning | Move services between groups, add and remove groups, save, request a plan, cancel |
| `planning` | The grouping, and the agent's steps as they arrive | Change the grouping (back to `grouping`), cancel |
| `awaiting_confirmation` | The plan: each VIP's IP, DNS names, certificate names and expiry, and services, each with its original origin and the URL that replaces it; the app's VIP and its whole rewrite map, `published` services included; the declaration; the dry-run diff; the warnings | Confirm, change the grouping (back to `grouping`), cancel |
| `deploying` | The confirmed plan, who confirmed it, and the agent's steps as they arrive | Nothing; a deploy in progress cannot be stopped |
| `deployed` | The confirmed plan, the F5 and DNS references | Nothing until decommissioning |
| `failed` | The step that failed, the agent's message and its step log; what the exposure holds | Retry, cancel |
| `cancelling`, `cancelled` | What is being or was released | Nothing |
| `superseded` | What was carried over, and a link to the exposure that replaced it | Nothing |

**What blocks planning.** The backend refuses to plan, and the workspace lists the reasons before the admin asks:

- a service not in exactly one group;
- an unexcluded Kerberos service (see Scope of an exposure);
- a `published` service whose registry entry has no URL (see Order of execution, step 6);
- an earlier exposure of the app still deploying (see Lifecycle).

The registry URL is set in the workspace itself, through the one non-exposure endpoint under Admin API.

**Warnings.** The backend attaches them to services; they do not block planning, and the confirm screen repeats them next to the confirm button:

- *Found only by the interceptor*: the service's `found_by` lacks the tracer, so its origin may be assembled at runtime and left unrewritten (see Rewriting).
- *Login redirect*: a `login_redirect` service; its identity provider must accept a redirect URI on the app's new name.

The scan does not record whether the app loads bundles with Subresource Integrity, so the confirm screen states that limit for every app rather than per service. Compressed responses are handled by the agent's template, not flagged per app (open question 4).

**Two admins at once.** Every write carries the version the admin was looking at. A write for an older version is refused, and the console reloads the exposure. A workspace open on an exposure follows its event stream, so a grouping saved by another admin shows up at once, with who saved it; if the admin has unsaved changes, the console says so and offers to reload, discarding them. A save moves the exposure back to `grouping` at once, so the console never shows a plan for a grouping that has since changed.

**Cancel and retry say what they will do.** Cancel lists what the exposure holds and will be released: IP reservations, certificates on the F5, DNS records. Retry names the step it resumes from. Both lists come from the agent's events, since the agent's own record is what it acts on.

## Admin API

Every endpoint here requires the `admin` role (see Identity). Errors follow the rest of the API: `404` for an unknown exposure, `409` for a request the exposure's status or version does not allow, with the current status and version in the body so the console can reload, and `422` for a malformed body.

| Method | Path | Does |
|---|---|---|
| `GET` | `/api/exposures` | The queue: open exposures, oldest submission first. `?status=` selects others, for the history |
| `GET` | `/api/exposures/{id}` | The workspace: status, version, app, scan, the services in scope with their groups, the `published` and excluded ones, warnings, what blocks planning, the current plan, who confirmed it, the failed step |
| `PUT` | `/api/exposures/{id}/groups` | Replace the grouping. Body: the version and the groups, each a list of service IDs and, to keep an existing group's ID, that ID; empty groups are dropped. Allowed in `grouping`, `planning` and `awaiting_confirmation`; moves the exposure to `grouping` and increments its version. A grouping that does not put each in-scope service in exactly one group is refused with an error per service |
| `POST` | `/api/exposures/{id}/plan` | Request a plan. Body: the version. `grouping` to `planning`; refused, with the reasons, while anything blocks planning |
| `POST` | `/api/exposures/{id}/confirm` | Approve the plan. Body: the version and the plan's hash. `awaiting_confirmation` to `deploying`; records who confirmed. Refused if the hash is not the current plan's |
| `POST` | `/api/exposures/{id}/retry` | Body: the version. `failed` to `planning` or `deploying`, resuming from the failed step |
| `POST` | `/api/exposures/{id}/cancel` | Body: the version. To `cancelled` from `grouping` if never planned; otherwise to `cancelling` from `grouping`, `planning`, `awaiting_confirmation` or `failed`. Increments the version, so a plan in flight is dropped. Refused in `deploying` and `deployed` |
| `GET` | `/api/exposures/{id}/events` | The exposure's event stream over SSE, resumable with `Last-Event-ID`, as a scan's is. Carries admin actions as well as the agent's steps; a closed exposure's stream replays and ends |
| `PATCH` | `/api/published-origins/{id}` | Set the URL of the VIP that publishes a registry entry added by hand |

Requesting a plan, confirming, retrying and cancelling are each a status change the backend makes in one transaction with the event that records it, so the event log and the status never disagree.

## Backend and agent protocol

The agent pulls; the backend never calls it. All agent endpoints are under their own prefix and accept only tokens issued to the agent (see Identity).

There is no job queue. The backend cannot hand work to the agent, so the work waits in the backend until the agent asks for it, but the exposures table already holds it: an exposure in `planning`, `deploying` or `cancelling` is waiting for the agent, and its status says what for.

| Method | Path | Does |
|---|---|---|
| `GET` | `/api/agent/pending` | The exposures waiting for the agent, oldest first, each with its status, version and payload |
| `POST` | `/api/agent/exposures/{id}/events` | Report step progress; each event carries a sequence number, so a repeat is ignored |
| `POST` | `/api/agent/exposures/{id}/result` | Report the outcome for a version; a result for an older version is ignored, and a repeat is too |

| Status | Payload | Result |
|---|---|---|
| `planning` | The app and its `url`, the VIP groups with each service's origin, auth method and pool member IPs, and the registry URLs of the `published` services it calls | Reserved IPs, DNS names, each VIP's certificate (names and expiry), the AS3 declaration, the dry-run diff, a hash of the plan |
| `deploying` | The hash of the plan the admin confirmed | Done, with the F5 and DNS references, or failed at a named step |
| `cancelling` | For a superseded exposure, the reservations the new one took over | Done |

Neither a payload nor a result ever carries a private key.

The agent polls every few seconds and works through the exposures one at a time, which AS3 requires anyway: it refuses a declaration while another is in progress.

The agent keeps its own record of what each exposure holds, its IP reservations, certificates and DNS records, and a step log keyed by exposure, version and step. An agent that restarts finds the exposure still `deploying` and resumes from the last step it completed, instead of reserving a second IP or creating a second record. A new plan reuses the reservations the exposure already holds and releases the ones it no longer needs, so a plan dropped for being stale leaks nothing. Likewise it reuses a VIP's certificate while the VIP's names are unchanged, and requests a new one only when they change, removing the old one from the F5. `cancelling` needs no list of what to undo; the agent already has it.

Exactly one agent may run. Two would both act on the same exposure. If a standby agent is ever needed, the agent API gains a lease and nothing else changes.

The backend turns the agent's events into the exposure's event stream, which the console reads over SSE as the scanner frontend reads a scan's.

The agent enforces its own limits, whatever the backend sends:

- It writes only to its own partitions, and never to the ones holding the VIPs of the exposure console, the backend and Keycloak.
- VIP addresses come only from the configured ranges, DNS records only in the configured zones.
- Declarations are rendered from the agent's own template; the backend sends data, never AS3.

## Identity

Both callers authenticate against the org's Keycloak, through its VIP, and the backend validates both kinds of token the same way.

| | Admin | Agent |
|---|---|---|
| Keycloak client | `exposure-console`, public, authorization code with PKCE | `exposure-agent`, confidential, service account enabled, standard flow off |
| Proves itself to Keycloak by | Signing in | Signed JWT: a private key on the agent host; Keycloak has the public key |
| Token carries | Client role `admin` of `exposure-api` | Client role `agent` of `exposure-api` |
| May call | The endpoints under Admin API | `/api/agent/*` only |

`exposure-api` is a bearer-only client that stands for the backend. Both clients get an audience mapper adding `exposure-api` to `aud`, which Keycloak leaves out by default. The F5 admin AD group is mapped to the `admin` role in Keycloak, so the backend checks a role rather than a group name; the `agent` role is assigned to the agent's service account only.

The backend checks, on every request, the token's signature against the realm's signing keys, which it fetches from Keycloak directly over the internal network; its issuer; that `aud` holds `exposure-api`; its expiry; and the role the endpoint requires. An agent token cannot confirm a deploy, and an admin token cannot report one.

Keycloak builds `iss` from the hostname it is reached by, so its hostname is fixed to the VIP's name (`KC_HOSTNAME`). Without that, tokens fetched through the VIP and the keys fetched directly would name different issuers.

The agent keeps its token until shortly before it expires and then requests a new one; client credentials get no refresh token. While Keycloak is down the agent stops polling and reporting once its token expires, and its step log lets it resume afterwards; admins cannot sign in then either.

`/me` and `submitted_by` are stubs today; the exposure endpoints must not reach production until this replaces them.

## Break-glass

The console, the backend API and Keycloak are all published through the F5 the agent configures. Their VIPs sit in partitions the agent is not allowed to write, and admins keep direct access to the F5 management GUI and CLI, so a bad deploy cannot take away the tool needed to fix it.

On the backend VIP, an LTM policy accepts `/api/agent/*` only from the agent host's address.

## Alternatives rejected

| Alternative | Why not |
|---|---|
| The browser calls the F5, IP reservation and DNS directly | Credentials in the browser; no retry, undo or audit |
| A deployer worker in this repo, claiming jobs from PostgreSQL | It would have to run on the management network and reach the internal database, the widest rule there is to open |
| A job queue for the agent, with claims, leases and heartbeats, as the scanners have | That machinery is for many workers competing for jobs. There is one agent, each exposure needs at most one thing at a time, and its status already says what |
| The browser relays plans between the backend and the agent | The agent cannot tell what the backend approved, and results are lost when the tab closes mid-deploy |
| DNS records created before the deploy | A name could resolve to an IP with nothing behind it, or an existing name be repointed before its VIP is live |
| The original hostnames recreated in the outside network's zone, so nothing needs rewriting | The agent would write names that mirror internal ones and can collide with records already in that zone, and every VIP would need a certificate for an internal name |
| A VIP as one IP with a virtual server per port | Most services are on 443, so few could share a VIP; the ones that could would need their outside URLs on non-standard ports |
| A VIP routing by SNI, passing TLS through | The F5 must decrypt anyway to rewrite responses and CORS headers, and an HTTP service would have nothing to terminate the TLS |
| Each VIP on its service's own scheme | The app's VIP serves HTTPS, so the browser blocks every call to an HTTP service's VIP as mixed content |
| Kerberos services marked `review` or `blocker` until v2 | Submit refuses those, so their apps could not be submitted at all; and the F5 can publish them, which v2 needs the severity to keep saying |
| Imperative iControl REST calls | Not idempotent and not atomic; AS3 gives dry runs and rollback by re-posting the previous declaration |
| The agent on the DMZ data plane | A host next to the internet would hold F5 credentials |
| mTLS between the agent and the backend | The backend VIP terminates TLS, so the backend never sees the client certificate unless the F5 forwards it in a header the backend must trust, or a passthrough VIP is added for the agent; and it needs a CA and rotation for one client. Keycloak already issues, revokes and audits credentials |
| A certificate's private key inline in the AS3 declaration | The declaration goes to the backend and the console, so the key would sit in the database and reach the admin's browser |
| A client secret for the agent | A shared secret sent on every token request; a signed JWT sends only proof of a key that never leaves the agent host |

## Open questions

1. **DNS naming convention.** A name is formed from the service's original host, in an external zone such as `example.com`. Still to settle: the exact form of a name given its host, and how two origins on the same host, differing only in scheme or port, get distinct names.
2. **The DNS service.** The DNS team's service creates the records and issues each VIP's certificate, generating its key; the agent calls it with the details. Still to learn: its API for both, whether creating and deleting a record are idempotent, how it delivers the key and protects it in transit, how long issuing takes, whether a certificate can be revoked when a plan is dropped or cancelled, and who renews certificates before they expire.
3. **The IP reservation service.** Its API: reserve and release, idempotency, whether a reservation expires.
4. **How the F5 rewrites.** A rewrite profile in URI-translation mode, or a stream profile with an iRule: which the AS3 version in use supports, and how each handles compressed and chunked bodies and the headers listed under Rewriting.
5. **The agent's source address.** Whether the backend VIP's source allowlist may include the agent. If not, the fallback is the browser relaying signed plans, with the costs listed above.
6. **The F5 itself.** AS3 version, single device or HA pair, existing partition conventions, and where the agent may install certificates and keys, given that it writes only to its own partitions.
7. **Keycloak.** Which realm the clients go in, whether the AD groups already reach it through LDAP federation, and whether `KC_HOSTNAME` is already set to the VIP's name.

## Phases

1. **Discovery**: answers to the open questions; API specs for the IP reservation and DNS services.
2. **Read-only**: exposures created on submit, the queue and detail endpoints, the console's queue and workspace against mocked data.
3. **Grouping**: saving and validating groups in the backend, the grouping UI.
4. **Planning**: the agent protocol, the agent with fake adapters, IP reservation, certificate requests, AS3 rendering with the app's rewrite map and dry run, the confirm screen.
5. **Deploy**: deploy, verify, DNS, registry, retry and undo, live progress; end to end against a lab BIG-IP VE. Built against the fake adapters; the lab run waits on Discovery.
6. **Hardening**: real authentication and roles, the audit view, decommissioning a VIP.

## Later

- **Kerberos services (v2).** The F5 has an APM licence. Each Kerberos service's VIP gets an access profile that signs the outside user in, and an SSO profile that obtains a ticket for the service's original name through Kerberos constrained delegation. This needs a delegation account in AD, with delegation rights to each service's SPN, which the AD team sets up; planning then checks that it exists for every Kerberos service in the exposure. Still to settle: how outside users sign in, and whether the agent may write APM objects to its partitions. The app's own auth method must be recorded too, so that an app that signs its users in with Kerberos is caught.
