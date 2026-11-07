# Exposure: publishing submitted apps through the F5

Status: draft. Nothing here is built yet.

A second frontend, for the F5 BIG-IP administrators, that takes each submitted app the rest of the way: it shows the external services the app calls that still need a VIP, lets the admin decide which services share a VIP, reserves the IP addresses, deploys the VIPs to the F5 and creates their DNS records.

Three parts:

| Part | Lives | Does |
|---|---|---|
| **Exposure console** (new frontend) | Internal network, published through the F5 | The queue, grouping, review and confirm, deploy progress, history |
| **Backend** (this repo) | Internal network | Owns the exposure records, validation, approval and audit; queues work for the agent |
| **Deployment agent** (new service) | Management network | The only holder of F5, IP-reservation and DNS credentials; carries out the plans the backend approved |

## Topology

```
Management network                F5 BIG-IP                  Internal network
------------------                ---------                  ----------------
admin browser     --HTTPS-->  VIP exposure-frontend  -->  exposure console (static files)
admin browser     --HTTPS-->  VIP exposure-api       -->  backend API --- PostgreSQL
deployment agent  --mTLS--->  VIP exposure-api       -->  backend API

deployment agent  -->  F5 management interface (AS3)
deployment agent  -->  IP reservation ("DHCP") service
deployment agent  -->  DNS service
```

Every arrow points from the side that opens the connection. The internal network cannot reach the management network, and nothing here needs it to: the agent polls the backend for work and reports back on the same connection. The admin's browser talks only to the backend, never to the agent.

| Secret | Held by |
|---|---|
| F5 credentials, IP-reservation and DNS write credentials | The agent only |
| The agent's mTLS client certificate | The agent; the backend trusts its CA |
| Database credentials | The backend only, as today |

## Scope of an exposure

An exposure is created for every submission, in the same transaction as `POST /scans/{id}/submit`, so the queue can never miss one. It is pinned to that scan.

Its services are the scan's services with severity `cleared` that are not excluded: the F5 can publish them and no one has yet. The console shows the rest read-only for context:

- `published` services are already on the F5 and get no VIP.
- Excluded services are out of scope.
- A submitted scan has no unexcluded `blocker` or `review` services; submit refuses them.

Each service already carries what its VIP needs: `scheme`, `host` and `port` are the listener, and `ips` are the pool members.

Each time the backend queues a plan, it re-reads the published-origins registry. A service whose origin was registered after the scan, for example by another app's exposure, is dropped from scope as published. This is what keeps two apps that call the same backend from getting two VIPs for it.

## Lifecycle

```
grouping --> planning --> awaiting_confirmation --> deploying --> deployed
   ^                            |
   +----------------------------+  (admin changes the grouping)
```

| Status | Means | Leaves by |
|---|---|---|
| `grouping` | The admin is arranging services into VIPs | Requesting a plan |
| `planning` | The agent is reserving IPs, rendering AS3 and running a dry run | The agent's result |
| `awaiting_confirmation` | The plan and its dry-run diff are ready for the admin | Confirm, or a change to the grouping (back to `grouping`) |
| `deploying` | The agent is deploying, verifying and creating DNS records | The agent's result |
| `deployed` | Live; origins registered as published | Terminal (decommissioning comes later) |
| `failed` | A plan or deploy gave up; the agent's step log says where | Retry (resumes) or cancel |
| `cancelled` | The admin cancelled before deploying; reservations released | Terminal |
| `superseded` | A newer submission of the app replaced it before deploying | Terminal |

A new submission while an exposure is open supersedes it. The new exposure starts from the old one's grouping for the origins they share and reuses its IP reservations; reservations it no longer needs are released. A new submission after a deploy needs no special case: the deployed origins are in the registry, so the next scan reads them as `published` and the new exposure covers only what changed.

## Grouping

The admin puts each in-scope service into exactly one VIP group. The default proposal is one VIP per host. The backend validates every save; the console only displays the errors.

The rules depend on what sharing a VIP means (see open questions). If a shared VIP is one IP with a virtual server per port, two services on the same port cannot share it. If it is one virtual server that routes by Host header or SNI, they can, but every service on it must use the same scheme and the VIP's certificate must cover all their names.

## Order of execution

1. **Plan** (on request, before confirmation): reserve one IP per VIP, render the AS3 declaration, dry-run it against the F5. The admin sees the IPs, the DNS names that will be created, the declaration and the dry-run diff.
2. **Confirm**: the admin approves that exact plan.
3. **Deploy**: dry-run again and stop if the diff differs from the approved one (the F5 drifted, or a reservation expired); otherwise post the declaration.
4. **Verify**: each virtual server is up and its pool members answer.
5. **DNS**: create the records, only now, so no name ever resolves to an IP that nothing is listening on.
6. **Register**: the backend adds each origin to the published-origins registry, pointing at its VIP.

A failure stops at that step. Retry resumes from it; cancel undoes the completed steps in reverse.

## Backend and agent protocol

The agent pulls; the backend never calls it. All agent endpoints are under their own prefix, accept only the agent's client certificate, and are never served to browsers.

| Method | Path | Does |
|---|---|---|
| `POST` | `/api/agent/operations/claim` | Lease the oldest pending operation. Returns it, or 204 when there is none |
| `POST` | `/api/agent/operations/{id}/heartbeat` | Extend the lease; a lapsed lease makes the operation claimable again |
| `POST` | `/api/agent/operations/{id}/events` | Report step progress; each event carries a sequence number, so a repeat is ignored |
| `POST` | `/api/agent/operations/{id}/result` | Report the outcome; idempotent |

An operation is one of:

| Kind | Payload | Result |
|---|---|---|
| `plan` | Exposure id and version, the app, the VIP groups with each service's origin, auth method and pool member IPs, reservations to reuse | Reserved IPs, DNS names, the AS3 declaration, the dry-run diff, a hash of the plan |
| `deploy` | The plan's hash | Done, with the F5 and DNS references, or failed at a named step |
| `release` | Reservations and DNS records to undo | Done |

The operation id is the idempotency key. The agent keeps its own step log keyed by operation and step, so an agent that restarts mid-operation, or loses its lease and claims the operation again, resumes where it stopped instead of reserving a second IP or creating a second record.

The backend turns the agent's events into the exposure's event stream, which the console reads over SSE as the scanner frontend reads a scan's.

The agent enforces its own limits, whatever the backend sends:

- It writes only to its own partitions, and never to the one holding the exposure console's and backend's VIPs.
- VIP addresses come only from the configured ranges, DNS records only in the configured zones.
- Declarations are rendered from the agent's own template; the backend sends data, never AS3.

## Identity

Admins sign in through the identity provider; the backend checks membership of the F5 admin group on every exposure write. The agent is identified by its client certificate. `/me` and `submitted_by` are stubs today; the exposure endpoints must not reach production until real authentication replaces them.

## Break-glass

The console and the backend API are published through the F5 they configure. Their VIPs sit in a partition the agent is not allowed to write, and admins keep direct access to the F5 management GUI and CLI, so a bad deploy cannot take away the tool needed to fix it.

## Alternatives rejected

| Alternative | Why not |
|---|---|
| The browser calls the F5, IP reservation and DNS directly | Credentials in the browser; no retry, undo or audit |
| A deployer worker in this repo, claiming jobs from PostgreSQL | It would have to run on the management network and reach the internal database, the widest rule there is to open |
| The browser relays plans between the backend and the agent | The agent cannot tell what the backend approved, and results are lost when the tab closes mid-deploy |
| DNS records created before the deploy | A name could resolve to an IP with nothing behind it, or an existing name be repointed before its VIP is live |
| Imperative iControl REST calls | Not idempotent and not atomic; AS3 gives dry runs and rollback by re-posting the previous declaration |
| The agent on the DMZ data plane | A host next to the internet would hold F5 credentials |

## Open questions

1. **What does sharing a VIP mean?** One IP with a virtual server per port, or one virtual server routing by Host header or SNI to separate pools. Decides the grouping rules and the AS3 template.
2. **DNS names.** The original internal hostnames republished in an external zone, or new names, which means reconfiguring the app.
3. **TLS certificates.** Who issues the certificate for each VIP, and how it reaches the agent.
4. **The IP reservation service.** Its API: reserve and release, idempotency, whether a reservation expires.
5. **The app's own URL.** Does it need a VIP too, or only the services it calls?
6. **Kerberos services.** They clear, but publishing them needs APM and SSO configuration as well as a virtual server and pool. In scope or not?
7. **Approval.** Who may confirm a deploy, and whether production needs a second approver.
8. **The agent's source address.** Whether the backend VIP's source allowlist may include the agent. If not, the fallback is the browser relaying signed plans, with the costs listed above.
9. **Reachability from the management network.** The identity provider for admin sign-in, and the IP reservation and DNS services for the agent.
10. **The F5 itself.** AS3 version, single device or HA pair, existing partition conventions.

## Phases

1. **Discovery**: answers to the open questions; API specs for the IP reservation and DNS services.
2. **Read-only**: exposures created on submit, the queue and detail endpoints, the console's queue and workspace against mocked data.
3. **Grouping**: saving and validating groups in the backend, the grouping UI.
4. **Planning**: the agent protocol, the agent with fake adapters, IP reservation, AS3 rendering and dry run, the confirm screen.
5. **Deploy**: deploy, verify, DNS, registry, retry and undo, live progress; end to end against a lab BIG-IP VE.
6. **Hardening**: real authentication and roles, the audit view, decommissioning a VIP.
