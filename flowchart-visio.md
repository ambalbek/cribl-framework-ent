# Cribl Framework — Visio Flowchart Reference

Use this document to recreate the application flowcharts in Microsoft Visio.
Each section describes shapes, connections, and swim lanes.

---

## 1. Authentication Flow (SAML 2.0 + Local Fallback)

### Swim Lanes
| Lane | Actor |
|------|-------|
| 1 | User / Browser |
| 2 | Cribl Framework (Flask) |
| 3 | ForgeRock IdP |

### Shapes

| # | Shape | Text | Lane | Color |
|---|-------|------|------|-------|
| A1 | Rounded Rectangle (Start) | User visits any page | 1 | Green |
| A2 | Diamond (Decision) | Session valid? | 2 | Yellow |
| A3 | Rectangle (Process) | Redirect to /login | 2 | Blue |
| A4 | Rectangle (Process) | Show login page (SSO button + local fallback) | 2 | Blue |
| A5 | Diamond (Decision) | SSO or Local? | 1 | Yellow |
| A6 | Rectangle (Process) | Redirect to ForgeRock SSO URL with SAML AuthnRequest | 2 | Blue |
| A7 | Rectangle (Process) | User authenticates on ForgeRock | 3 | Purple |
| A8 | Rectangle (Process) | ForgeRock POSTs SAML Response to /saml/acs | 3 | Purple |
| A9 | Rectangle (Process) | Validate SAML assertion + extract attributes | 2 | Blue |
| A10 | Diamond (Decision) | Assertion valid? | 2 | Yellow |
| A11 | Rectangle (Process) | Extract username, display_name, groups from SAML attributes | 2 | Blue |
| A12 | Rectangle (Process) | User enters username + password in local form | 1 | Gray |
| A13 | Rectangle (Process) | POST /login - check local_admins + local_users | 2 | Gray |
| A14 | Diamond (Decision) | Credentials match? | 2 | Yellow |
| A15 | Rectangle (Process) | Resolve role from groups (admin or user) | 2 | Blue |
| A16 | Diamond (Decision) | Role assigned? | 2 | Yellow |
| A17 | Rectangle (Process) | Create Flask session (username, role, display_name) | 2 | Blue |
| A18 | Diamond (Decision) | Role = user? | 2 | Yellow |
| A19 | Rectangle (Process) | Redirect to /portal | 2 | Blue |
| A20 | Rectangle (Process) | Redirect to requested page | 2 | Blue |
| A21 | Rounded Rectangle (End) | User is authenticated | 1 | Green |
| A22 | Rectangle (Process) | Show error: "Auth failed" or "Not authorized" | 2 | Red |
| A23 | Rectangle (Process) | Allow access - page renders | 2 | Green |

### Connections

| From | To | Label |
|------|----|-------|
| A1 | A2 | |
| A2 | A23 | Yes (session exists) |
| A2 | A3 | No |
| A3 | A4 | |
| A4 | A5 | |
| A5 | A6 | SSO |
| A5 | A12 | Local |
| A6 | A7 | Browser redirect |
| A7 | A8 | POST |
| A8 | A9 | |
| A9 | A10 | |
| A10 | A11 | Yes |
| A10 | A22 | No |
| A11 | A15 | |
| A12 | A13 | POST |
| A13 | A14 | |
| A14 | A15 | Yes |
| A14 | A22 | No |
| A15 | A16 | |
| A16 | A17 | Yes |
| A16 | A22 | No (no matching group) |
| A17 | A18 | |
| A18 | A19 | Yes |
| A18 | A20 | No (admin) |
| A19 | A21 | |
| A20 | A21 | |
| A22 | A4 | Back to login |

---

## 2. End-to-End Onboarding Workflow

### Swim Lanes
| Lane | Actor |
|------|-------|
| 1 | Client (User role) |
| 2 | Cribl Framework |
| 3 | Elasticsearch |
| 4 | Platform Team (Admin role) |
| 5 | Cribl Stream |

### Shapes

| # | Shape | Text | Lane | Color |
|---|-------|------|------|-------|
| B1 | Rounded Rectangle (Start) | Client logs in via SSO | 1 | Green |
| B2 | Rectangle (Process) | Open /portal - onboarding form | 1 | Blue |
| B3 | Rectangle (Process) | Username + name auto-populated from session | 2 | Blue |
| B4 | Rectangle (Process) | Fill: APM ID, App Name, Region, Log Dest, Log Type, Entitlement Groups | 1 | Blue |
| B5 | Rectangle (Process) | POST /portal/api/submit | 2 | Blue |
| B6 | Rectangle (Process) | Validate + build ES document | 2 | Blue |
| B7 | Rectangle (Data) | Index document: status = "pending" | 3 | Orange |
| B8 | Rectangle (Process) | Return REQ-YYYYMMDD-XXXXXXXX | 2 | Blue |
| B9 | Rounded Rectangle (End) | Client sees Request ID | 1 | Green |
| B10 | Rounded Rectangle (Start) | Admin logs in via SSO | 4 | Green |
| B11 | Rectangle (Process) | Open /cribl/app - Pusher UI | 4 | Blue |
| B12 | Rectangle (Process) | Paste Request ID, select workspace + worker groups | 4 | Blue |
| B13 | Diamond (Decision) | Dry Run? | 2 | Yellow |
| B14 | Rectangle (Process) | Preview diff - no writes | 2 | Gray |
| B15 | Rectangle (Process) | Create destinations in Cribl | 5 | Purple |
| B16 | Rectangle (Process) | PATCH routes in Cribl | 5 | Purple |
| B17 | Rectangle (Process) | Create ELK roles + role-mappings | 3 | Orange |
| B18 | Rectangle (Process) | Auto-update status = "done" | 3 | Orange |
| B19 | Rounded Rectangle (End) | Request completed | 4 | Green |
| B20 | Rectangle (Process) | Open /entitlements - verify role mappings | 1 or 4 | Blue |

### Connections

| From | To | Label |
|------|----|-------|
| B1 | B2 | |
| B2 | B3 | |
| B3 | B4 | |
| B4 | B5 | Submit |
| B5 | B6 | |
| B6 | B7 | |
| B7 | B8 | |
| B8 | B9 | |
| B10 | B11 | |
| B11 | B12 | |
| B12 | B13 | Run |
| B13 | B14 | Yes |
| B13 | B15 | No |
| B14 | B12 | Review & retry |
| B15 | B16 | |
| B16 | B17 | If rode_rm mode |
| B17 | B18 | |
| B16 | B18 | If pusher mode |
| B18 | B19 | |
| B19 | B20 | Optional |

---

## 3. RBAC Access Matrix

### Visio Table Shape

| Page / Feature | Route | User Role | Admin Role | Auth Required |
|----------------|-------|-----------|------------|---------------|
| Login Page | /login | Public | Public | No |
| Logout | /logout | Public | Public | No |
| Health Check | /health | Public | Public | No |
| ES Health | /health/es | Public | Public | No |
| SAML SSO Login | /saml/login | Public | Public | No |
| SAML ACS | /saml/acs | Public | Public | No |
| SP Metadata | /saml/metadata | Public | Public | No |
| Landing Page | / | Redirect to /portal | Full dashboard | Yes |
| Onboarding Portal | /portal | Allowed | Allowed | Yes |
| Submit Request API | /portal/api/submit | Allowed | Allowed | Yes |
| Entitlement Lookup | /entitlements | Allowed | Allowed | Yes |
| Entitlements API | /api/entitlements | Allowed | Allowed | Yes |
| Cribl Pusher UI | /cribl/app | Blocked (403) | Allowed | Yes (Admin) |
| Run Pusher API | /cribl/api/run-pusher | Blocked (403) | Allowed | Yes (Admin) |
| Run RODE-RM API | /cribl/api/run-rode-rm | Blocked (403) | Allowed | Yes (Admin) |
| Admin Panel | /portal/admin/update-status | Blocked (403) | Allowed | Yes (Admin) |

---

## 4. Application Architecture

### Visio Block Diagram

```
+--------------------------------------------------+
|                    Browser                        |
+--------------------------------------------------+
           |                          |
           v                          v
+---------------------+   +----------------------+
| ForgeRock IdP       |   | Cribl Framework      |
| (SAML 2.0)          |   | Flask :5000          |
|                     |   |                      |
| /SSORedirect        |<--| /saml/login          |
| (AuthnRequest)      |   | /saml/acs            |
|                     |-->| /saml/metadata       |
| SAML Response       |   |                      |
+---------------------+   | Routes:              |
                           | /login               |
                           | /portal              |
                           | /cribl/app           |
                           | /entitlements        |
                           | /portal/admin        |
                           +----------+-----------+
                                      |
              +-----------+-----------+-----------+
              |           |                       |
              v           v                       v
   +------------------+  +------------------+  +------------------+
   | Elasticsearch    |  | Cribl Stream     |  | config.json      |
   | Clusters         |  | API              |  |                  |
   |                  |  |                  |  | - SAML SP/IdP    |
   | - Onboarding     |  | - Routes         |  | - Local accounts |
   |   requests       |  | - Destinations   |  | - Workspaces     |
   | - Role mappings  |  | - Worker groups  |  | - ES clusters    |
   |   (entitlements) |  |                  |  | - Role mappings  |
   +------------------+  +------------------+  +------------------+
```

### Visio Shape Definitions for Architecture

| # | Shape | Text | Color | Notes |
|---|-------|------|-------|-------|
| C1 | Rectangle | Browser | Light Gray | Top center |
| C2 | Rectangle | ForgeRock IdP (SAML 2.0) | Purple | Left side |
| C3 | Rectangle | Cribl Framework (Flask :5000) | Blue | Center |
| C4 | Rectangle | Elasticsearch Clusters | Orange | Bottom left |
| C5 | Rectangle | Cribl Stream API | Red | Bottom center |
| C6 | Rectangle | config.json | Gray | Bottom right |

### Connections for Architecture

| From | To | Label | Line Style |
|------|----|-------|------------|
| C1 | C3 | HTTPS | Solid |
| C1 | C2 | SAML Redirect | Dashed |
| C2 | C3 | SAML Response (POST /saml/acs) | Solid |
| C3 | C2 | AuthnRequest (GET /saml/login) | Dashed |
| C3 | C4 | Onboarding docs + Role mappings | Solid |
| C3 | C5 | Routes + Destinations | Solid |
| C3 | C6 | Read config | Dotted |

---

## 5. Entitlement Lookup Flow

### Shapes

| # | Shape | Text | Lane | Color |
|---|-------|------|------|-------|
| D1 | Rounded Rectangle (Start) | User opens /entitlements | User | Green |
| D2 | Rectangle (Process) | GET /api/entitlements | Framework | Blue |
| D3 | Rectangle (Process) | Load entitlement config from config.json | Framework | Blue |
| D4 | Subprocess | For each ES cluster | Framework | Blue |
| D5 | Rectangle (Process) | GET /_security/role_mapping (HTTPBasicAuth) | ES Cluster | Orange |
| D6 | Rectangle (Process) | Extract entitlement CNs matching filter | Framework | Blue |
| D7 | Rectangle (Process) | Parse CN from DN, build result objects | Framework | Blue |
| D8 | Diamond (Decision) | Cluster error? | Framework | Yellow |
| D9 | Rectangle (Process) | Add error record (error: true) | Framework | Red |
| D10 | Rectangle (Process) | Sort results by cluster + entitlement | Framework | Blue |
| D11 | Rectangle (Process) | Return JSON array | Framework | Blue |
| D12 | Rectangle (Process) | Render table with search, filter, sort, pagination | Browser | Green |
| D13 | Rounded Rectangle (End) | User views/exports entitlements | User | Green |

### Connections

| From | To | Label |
|------|----|-------|
| D1 | D2 | |
| D2 | D3 | |
| D3 | D4 | |
| D4 | D5 | Per cluster |
| D5 | D6 | Response |
| D6 | D7 | |
| D7 | D8 | |
| D8 | D9 | Yes |
| D8 | D4 | No (next cluster) |
| D9 | D4 | Next cluster |
| D4 | D10 | All clusters done |
| D10 | D11 | |
| D11 | D12 | JSON |
| D12 | D13 | |

---

## Visio Color Legend

| Color | Hex | Usage |
|-------|-----|-------|
| Green | #22c55e | Start/End terminators, success states |
| Blue | #0284c7 | Framework processes |
| Yellow | #f59e0b | Decision diamonds |
| Orange | #f97316 | Elasticsearch operations |
| Purple | #8b5cf6 | ForgeRock / external IdP |
| Red | #e53e3e | Error states, blocked access |
| Gray | #94a3b8 | Local fallback, optional paths |

## Visio Shape Legend

| Shape | Usage |
|-------|-------|
| Rounded Rectangle | Start / End |
| Rectangle | Process step |
| Diamond | Decision / branch |
| Parallelogram | Data / document |
| Subprocess (double-sided rectangle) | Loop / iteration |
