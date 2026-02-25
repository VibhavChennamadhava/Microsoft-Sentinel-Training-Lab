# Microsoft Sentinel Training Lab — End-to-End Hands-On (8 Modules)

## Introduction
This repository documents my end-to-end completion of the Microsoft Sentinel Training Lab across all eight modules. I used a SOC-analyst workflow mindset to go from initial workspace onboarding to detections, investigation, hunting, threat intelligence, and solution expansion through Content hub.

From an operations perspective, this lab maps directly to real SOC activities: ingesting and normalizing telemetry, enabling detections, triaging and investigating incidents, reducing false positives, and improving coverage with threat intel and solution content.

## Learning Outcomes
- Onboarded a Log Analytics workspace and enabled Microsoft Sentinel as a cloud-native SIEM layer.
- Connected key data sources (Azure Activity, Microsoft Defender for Cloud, and Threat Intelligence TAXII).
- Created and tuned analytics rules, including scheduled rules with entity mapping and incident settings.
- Practiced incident lifecycle handling: assignment, investigation, enrichment, automation, and closure.
- Executed threat hunting workflows with MITRE ATT&CK filtering, bookmarks, and investigation graph pivots.
- Implemented watchlists and used KQL exclusions to reduce noise/false positives.
- Added and validated threat intelligence indicators and related analytics/workbook content.
- Installed and validated new detections/workbooks/hunts through Content hub solutions.

## Prerequisites
- Azure subscription (Student/Free/Pay-As-You-Go).
- Log Analytics workspace (new or existing).
- Microsoft Sentinel onboarding to the workspace.
- Access to this repo, including all evidence images in `screenshots/`.

> 💡 **Cost-Safety Note:** I kept ingestion controlled by using training data and only enabling required connectors. In a real environment, I would apply ingestion caps, retention governance, and selective data collection to prevent unnecessary cost.

> 💡 **Repo Note:** All screenshots are embedded from the `screenshots/` folder using relative paths.

## Table of Contents
- [Introduction](#introduction)
- [Learning Outcomes](#learning-outcomes)
- [Prerequisites](#prerequisites)
- [Module 1 — Environment setup](#module-1--environment-setup)
- [Module 2 — Data connectors](#module-2--data-connectors)
- [Module 3 — Analytics rules](#module-3--analytics-rules)
- [Module 4 — Incident management](#module-4--incident-management)
- [Module 5 — Hunting](#module-5--hunting)
- [Module 6 — Watchlists](#module-6--watchlists)
- [Module 7 — Threat intelligence](#module-7--threat-intelligence)
- [Module 8 — Content hub](#module-8--content-hub)
- [Troubleshooting & UI Changes](#troubleshooting--ui-changes)
- [Conclusion / Next Steps](#conclusion--next-steps)

---

## Module 1 — Environment setup
### Goal
Set up the Sentinel lab foundation: workspace selection, Sentinel onboarding, training solution deployment, and required authorization steps.

### Steps I performed
1. Created/selected the Log Analytics workspace for the lab.
2. Added Microsoft Sentinel to that workspace.
3. Deployed the Sentinel Training Lab solution to load the pre-recorded lab content.
4. Reviewed deployment parameters and completed post-deployment authorization for playbook/API connections.

![Log Analytics workspace selection](screenshots/workspace.png)
![Adding Sentinel to workspace](screenshots/sentinel_adding.png)
![Sentinel onboarding wizard](screenshots/sentinel_wizard-1.png)
![Deploying training solution](screenshots/deploy_training_solution.png)
![Deployment parameters](screenshots/params.png)
![Authorizing connections](screenshots/authorizing.png)

### Validation / expected result
✅ Validation:
- Sentinel opened successfully against the target workspace.
- Training Lab solution deployment completed without blocking errors.
- Required connections were authorized and available for later modules.

### Troubleshooting / gotchas
- Ensure you are in the **correct subscription + workspace context** before onboarding Sentinel.
- If deployment appears stalled, check **resource group deployments** for detailed failure causes.
- Playbook/API authorization often requires explicit sign-in and consent after deployment.

### Module Summary
- I established the full SIEM workspace baseline and onboarded Sentinel.
- I deployed the official training solution to preload lab-friendly data and artifacts.
- I completed required authorization tasks so automation/investigation actions could run.
- I learned to validate onboarding and deployment health before enabling analytics content.

---

## Module 2 — Data connectors
### Goal
Enable key data connectors required by the lab and validate ingestion paths in the current Sentinel UI.

### Steps I performed
1. Opened Sentinel connectors (via **Content hub/Data connectors** depending on portal view).
2. Configured **Azure Activity** using the modern diagnostic settings/policy-based pipeline.
3. Connected **Microsoft Defender for Cloud**.
4. Configured **Threat Intelligence TAXII** feed.
5. Validated connection status and ingestion indicators.

![Azure Activity connector page](screenshots/azure_activity.png)
![Creating Azure Activity connection](screenshots/creating_azure_activity.png)
![Setting Azure Activity pipeline](screenshots/setting_azure_activity.png)
![Enable Defender for Cloud connector](screenshots/enabling_connector_cloud.png)
![Adding Microsoft Defender source](screenshots/adding_microsoftdefender.png)
![TAXII connector](screenshots/taxii.png)
![TAXII configuration step](screenshots/taxii_2.png)
![TAXII success status](screenshots/taxi_success.png)

> ⚠️ **UI Update Note:** In newer Sentinel experiences, some connector paths moved between **Content hub** and **Data connectors**, and filters can hide “Not connected” sources.

### Validation / expected result
✅ Validation:
- Azure Activity path showed configured diagnostic/policy-based collection.
- Defender for Cloud connector status reflected enabled integration.
- TAXII connector showed successful connection status.

### Troubleshooting / gotchas
- If a connector is missing, clear filters and set **Status = All**.
- Azure Activity setup screens may display modernization/deprecation notes; follow current diagnostic settings/policy guidance.
- TAXII feeds can fail due to endpoint/provider availability; validate feed URL/credentials and retry interval.

### Module Summary
- I enabled core data sources needed for Sentinel detections and investigations.
- I adapted to UI changes while preserving expected connector outcomes.
- I confirmed ingestion/connection health before moving to analytics configuration.
- I learned practical connector troubleshooting for modernized Sentinel workflows.

---

## Module 3 — Analytics rules
### Goal
Create and tune analytics using templates and custom KQL to generate actionable incidents.

### Steps I performed
1. Reviewed analytics **rule templates** and filtered by relevant source/category.
2. Created the modern equivalent of the “Microsoft incident creation rule” path via templates/connector-driven content.
3. Reviewed and enabled **Fusion (Advanced multistage attack detection)** where available.
4. Built a **custom scheduled analytic rule** with KQL.
5. Configured entity mapping, schedule frequency, event grouping, and incident creation settings.
6. Triggered/validated incident generation.

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4625, 4624)
| summarize FailedAttempts = countif(EventID == 4625), SuccessfulLogons = countif(EventID == 4624) by Account, Computer
| where FailedAttempts > 5
| project TimeGenerated=now(), Account, Computer, FailedAttempts, SuccessfulLogons
```

![Analytics create menu](screenshots/create.png)
![Creating analytics rule](screenshots/creating_rule.png)
![Scheduled rule query authoring](screenshots/creating_scheduled_rule_query.png)
![Scheduled rule query tuning](screenshots/creating_scheduled_rule_query2.png)
![Alert grouping settings](screenshots/alertgrouping.png)
![Rule created](screenshots/rule_created.png)
![Incidents generated](screenshots/incidents.png)

> ⚠️ **UI Update Note:** If “Microsoft incident creation rule” is not visible as a standalone option, use current **Rule templates / Microsoft security templates** or create equivalent scheduled logic with incident creation enabled.

### Validation / expected result
✅ Validation:
- Rule deployed in the analytics list with enabled status.
- Incident(s) generated and visible in the incident queue.
- Entities and alert details were attached per mapping/grouping configuration.

### Troubleshooting / gotchas
- Template availability depends on enabled connectors and workspace content.
- If no incidents are generated, widen time range and lower thresholds for test conditions.
- Verify incident creation toggle is enabled in the rule wizard.

### Module Summary
- I used both template-driven and custom rule creation paths.
- I implemented KQL detection logic and mapped entities for better investigation context.
- I confirmed that configured detections produced incidents as expected.
- I learned that rule availability and behavior depend heavily on connector state and UI version.

---

## Module 4 — Incident management
### Goal
Execute incident triage-to-closure workflow including investigation pivots, playbook runs, tags, automation, and case closure.

### Steps I performed
1. Opened incident queue and prioritized active alerts.
2. Assigned incidents, updated status, and reviewed full details.
3. Investigated evidence through entities, timeline, logs, and workbook pivots.
4. Ran playbook action manually where applicable.
5. Added tags/comments and created automation rule from incident context.
6. Closed the incident with classification and analyst notes.
7. Followed the Solarigate/Solargate-style example flow used in the lab scenario.

![Incident queue](screenshots/lab4_incidents.png)
![Incident handling workflow](screenshots/lab4_handingOverincident.png)
![Solarigate scenario evidence](screenshots/lab4_solarigate.png)
![Events and timeline context](screenshots/Lab4_events.png)
![IOC and entities context](screenshots/Lab4_IOC-entities.png)
![Add IOC/entity workflow](screenshots/Lab4_addiingIOC.png)
![Manual playbook run](screenshots/lab4_playbookrun.png)
![Automation rule creation](screenshots/lab4_automationrule.png)
![Incident closure](screenshots/lab4_incidentclosing.png)

### Validation / expected result
✅ Validation:
- Incident ownership/status reflected analyst workflow updates.
- Investigation graph/timeline displayed relevant entities and evidence.
- Automation and playbook actions executed successfully.
- Incident closed with classification and closure rationale.

### Troubleshooting / gotchas
- Playbook execution can fail if API/connection authorization is incomplete.
- Entity pages differ by incident source; use logs and relationships to pivot reliably.
- Always add closure comments for auditability and handoffs.

### Module Summary
- I completed full incident lifecycle handling from triage to documented closure.
- I used Sentinel investigation tools (entities, logs, graph, automation) to enrich analysis.
- I practiced analyst handoff discipline with tags, notes, and classification.
- I learned how automation improves response consistency in repeatable scenarios.

---

## Module 5 — Hunting
### Goal
Use hunting queries and bookmarks to convert exploratory findings into incident-ready evidence.

### Steps I performed
1. Opened the Hunting page and filtered by MITRE technique (e.g., **T1098**).
2. Ran selected hunting queries and reviewed result sets.
3. Created bookmarks from meaningful events.
4. Investigated bookmarks in graph view and linked findings.
5. Promoted bookmark findings into a new or existing incident.

![Hunting page](screenshots/Lab5_huntingpage.png)
![Hunting queries list](screenshots/lab5_hunting queries.png)
![Account manipulation hunt](screenshots/lab5_account_manipu.png)
![Hunt query results](screenshots/lab5_account_manipu_results.png)
![Creating bookmark](screenshots/Lab5-creating-bookmark.png)
![Bookmarks list](screenshots/lab5_bookmarks.png)
![Bookmark graph investigation](screenshots/lab5_bookmarks_investigation.png)
![Create incident from bookmark](screenshots/lab5_creatingincident.png)
![Incident created from bookmark](screenshots/lab5-incidentcreated.png)

### Validation / expected result
✅ Validation:
- Hunting query execution returned analyzable events.
- Bookmarks were created and visible in bookmark management.
- Bookmark findings were successfully promoted to incident workflow.

### Troubleshooting / gotchas
- MITRE-tagged query availability varies by content pack and workspace state.
- If results are empty, widen query timeframe and validate connector ingestion.
- Use consistent bookmark naming to simplify incident correlation.

### Module Summary
- I operationalized hunting results by turning findings into bookmarks and incidents.
- I practiced ATT&CK-aligned hunting and evidence pivoting via graph analysis.
- I learned how hunting and incident response workflows connect in a mature SOC process.

---

## Module 6 — Watchlists
### Goal
Use watchlists for contextual filtering and detection tuning to reduce false positives.

### Steps I performed
1. Created a watchlist from CSV data.
2. Queried watchlist entries in Logs to validate ingestion.
3. Updated an analytics rule to exclude trusted watchlist IPs.
4. Re-tested behavior to confirm reduced alert noise.

```kql
let TrustedIPs = (_GetWatchlist('trusted_ip_watchlist') | project SearchKey);
SecurityEvent
| where TimeGenerated > ago(24h)
| where IPAddress !in (TrustedIPs)
| summarize Count=count() by IPAddress, Account
| order by Count desc
```

![Create watchlist](screenshots/lab6_watchlistnew.png)
![Watchlist upload step](screenshots/lab6_watchlistnew2.png)
![Watchlist mapping step](screenshots/lab6_watchlistnew3.png)
![Watchlist review/create step](screenshots/lab6_watchlistnew4.png)
![Watchlist created](screenshots/lab6_watchlistcreated.png)
![Rule before watchlist exclusion](screenshots/lab6_creatingrule.png)
![Adding where clause exclusion](screenshots/lab6_addingwhereclause.png)
![Review updated rule](screenshots/lab6_reviewcreaterule.png)
![Reduced high-count noise](screenshots/lab6_highcount.png)

### Validation / expected result
✅ Validation:
- Watchlist entries resolved via `_GetWatchlist()` in KQL.
- Updated rule logic excluded known benign IPs.
- Alert volume/noise reduced compared to pre-tuning baseline.

### Troubleshooting / gotchas
- Ensure watchlist alias/name exactly matches KQL reference.
- CSV headers must align with intended `SearchKey` mapping.
- Rule changes may require a full schedule cycle before impact is visible.

### Module Summary
- I implemented watchlist ingestion and validated query-level enrichment.
- I tuned detection logic using watchlist exclusions to reduce false positives.
- I learned a repeatable pattern for precision tuning without losing detection intent.

---

## Module 7 — Threat intelligence
### Goal
Ingest and manage threat intel, add manual IOC objects, and validate TI-driven analytics/workbook value.

### Steps I performed
1. Reviewed TI tables/schema and TI management interface.
2. Connected TI feed path used in the lab and validated indicator visibility.
3. Added a manual IOC using the modern TI object flow (STIX pattern format).
4. Reviewed TI analytics templates and enabled/adjusted as needed.
5. Opened TI workbook and added/validated query visualization.

```text
[ipv4-addr:value = '203.0.113.50']
```

![TI connector in Sentinel](screenshots/lab7_connecting_threat_intelligence.png)
![TAXII platform indicators](screenshots/lab7_Taxi_platform_IOCs.png)
![Threat intel IOC list](screenshots/lab7_threatINT_IOCs.png)
![Adding IOC object](screenshots/lab7_addingIOC.png)
![IOC object created](screenshots/lab7_Created.png)
![Run TI query](screenshots/lab7_runing_query.png)
![Create TI-driven rule](screenshots/lab7_creating_rule.png)
![TI workbook](screenshots/lab7_workbooks.png)
![Add workbook query](screenshots/lab7_workbooks_adding.png)
![Workbook visualization](screenshots/lab7_resultbarchart.png)

> ⚠️ **UI Update Note:** In modern Sentinel, **Add** may prompt for **TI object** or **TI relationship** (instead of a simple legacy IOC form). Use TI object + STIX pattern for manual indicators.

### Validation / expected result
✅ Validation:
- TI objects/indicators appeared in TI management view and query results.
- TI-related analytics templates were available for enablement/tuning.
- Workbook visual confirmed TI data could be analyzed operationally.

### Troubleshooting / gotchas
- STIX pattern syntax must be correct or object creation fails.
- Some legacy TAXII demo feeds are unstable or retired; use active alternatives.
- TI template results depend on both indicator freshness and matching telemetry.

### Module Summary
- I completed TI management from ingestion through manual IOC creation and visualization.
- I adapted to modern TI object workflows and STIX-based entry requirements.
- I learned how TI enriches detection and contextual investigation in Sentinel.

---

## Module 8 — Content hub
### Goal
Install and verify solution content from Content hub to expand detection and investigation coverage.

### Steps I performed
1. Opened Content hub and reviewed available solutions.
2. Selected and installed a solution (Cloudflare/Dynamics-style lab flow).
3. Deployed included artifacts.
4. Verified new analytics rules, workbooks, and hunting queries.

![Content hub solution selection](screenshots/lab8_cloudflare.png)
![Dynamics solution deployment step](screenshots/lab8_dynamics_deployment.png)
![Dynamics deployment progress](screenshots/lab8_dynamics_deployment2.png)
![Dynamics deployment completed](screenshots/lab8_dynamics_deployment3.png)
![New analytics rules after install](screenshots/lab8_newrules.png)
![New workbooks after install](screenshots/lab8_workbooks.png)

### Validation / expected result
✅ Validation:
- Solution installed successfully and artifacts were deployed.
- New analytics/workbooks/hunts appeared in Sentinel and were available for enablement.
- Content hub expansion increased baseline SOC coverage.

### Troubleshooting / gotchas
- Artifacts may appear with delay; refresh and verify correct workspace scope.
- Some artifacts ship disabled by default and must be explicitly enabled.
- Solution dependencies can require connector readiness before full value is realized.

### Module Summary
- I used Content hub to extend Sentinel capabilities with packaged solution content.
- I validated post-install artifacts and confirmed operational availability.
- I learned how to scale SOC coverage quickly using curated integrations.

---

## Troubleshooting & UI Changes
### Sentinel solution deployment fails because workspace is not onboarded
- **Problem:** Training solution deployment fails or Sentinel content is unavailable.
- **Cause:** Log Analytics workspace exists, but Sentinel was not fully onboarded.
- **Fix:** Open Sentinel and use **Add to workspace** first, then redeploy the lab solution.

### Data connectors not visible / UI changed
- **Problem:** Expected connector does not show in the same location as older lab videos.
- **Cause:** Portal modernization moved items between **Content hub** and **Data connectors**, and filters hide entries.
- **Fix:** Clear connector filters and set **Status = All**; verify workspace scope and refresh.

### Azure Activity connector shows modernization/deprecation messaging
- **Problem:** Legacy Azure Activity flow appears deprecated.
- **Cause:** Collection pipeline moved toward diagnostic settings/Azure Policy-based onboarding.
- **Fix:** Enable subscription-level diagnostic settings or use policy wizard path for current pipeline.

### “Microsoft incident creation rule” missing from Create menu
- **Problem:** Exact legacy menu option is unavailable.
- **Cause:** Rule creation UX changed in modern Sentinel.
- **Fix:** Use **Rule templates / Microsoft security templates**, enable connector-provided content, or build equivalent scheduled analytic rule with incident creation enabled.

### Threat Intelligence Add workflow changed
- **Problem:** “Add” opens TI object/relationship forms instead of simple IOC fields.
- **Cause:** TI UI evolved to object-based model.
- **Fix:** Add a **TI object** using valid STIX pattern syntax, for example:
  ```text
  [ipv4-addr:value = '198.51.100.25']
  ```

### Legacy TAXII source instability (Anomali Limo / old lab references)
- **Problem:** TAXII feed timeouts or retired source behavior.
- **Cause:** Legacy public feeds can be rate-limited, unstable, or end-of-life.
- **Fix:** Use a working alternative feed (e.g., Pulsedive TAXII STIX endpoint) and set safe polling cadence (hourly/daily rather than aggressive intervals).

### Additional practical fixes used during the lab
- **Problem:** Expected content/templates unavailable after connector setup.
- **Cause:** Propagation delay or incomplete connector prerequisites.
- **Fix:** Wait for backend sync, refresh workspace context, confirm permissions, and re-open analytics templates.

---

## Conclusion / Next Steps
Completing this lab gave me a realistic, end-to-end Sentinel workflow from onboarding to operational detection and response. I finished with a tuned, evidence-backed SOC pipeline that I can now extend for production-style use cases.

Next steps I would take in a real SOC:
- Tune high-noise detections using baselines, watchlists, and suppression logic.
- Implement alert quality metrics to reduce analyst fatigue and improve triage speed.
- Expand connectors for identity, endpoint, cloud app, and network telemetry.
- Build automation roadmap (playbooks + automation rules) for repeatable containment actions.
- Formalize incident response playbooks and reporting dashboards for leadership visibility.
