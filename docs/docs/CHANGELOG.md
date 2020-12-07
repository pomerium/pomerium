# Changelog

## [v0.11.0](https://github.com/pomerium/pomerium/tree/v0.11.0) (2020-12-04)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.10.6...v0.11.0)

## Breaking

- remove deprecated cache\_service\_url config option [\#1614](https://github.com/pomerium/pomerium/pull/1614) (@calebdoxsey)
- add flag to enable user impersonation [\#1514](https://github.com/pomerium/pomerium/pull/1514) (@calebdoxsey)

## New

- microsoft: add support for common endpoint [\#1648](https://github.com/pomerium/pomerium/pull/1648) (@desimone)
- use the directory email when provided for the jwt [\#1647](https://github.com/pomerium/pomerium/pull/1647) (@calebdoxsey)
- fix profile image on dashboard [\#1637](https://github.com/pomerium/pomerium/pull/1637) (@calebdoxsey)
- wait for initial sync to complete before starting control plane [\#1636](https://github.com/pomerium/pomerium/pull/1636) (@calebdoxsey)
- authorize:  add signature algo support \(RSA / EdDSA\) [\#1631](https://github.com/pomerium/pomerium/pull/1631) (@desimone)
- replace GetAllPages with InitialSync, improve merge performance [\#1624](https://github.com/pomerium/pomerium/pull/1624) (@calebdoxsey)
- cryptutil: more explicit decryption error [\#1607](https://github.com/pomerium/pomerium/pull/1607) (@desimone)
- add paging support to GetAll [\#1601](https://github.com/pomerium/pomerium/pull/1601) (@calebdoxsey)
- attach version to gRPC server metadata [\#1598](https://github.com/pomerium/pomerium/pull/1598) (@calebdoxsey)
- use custom default http transport [\#1576](https://github.com/pomerium/pomerium/pull/1576) (@calebdoxsey)
- update user info in addition to refreshing the token [\#1572](https://github.com/pomerium/pomerium/pull/1572) (@calebdoxsey)
- databroker: add audience to session [\#1557](https://github.com/pomerium/pomerium/pull/1557) (@calebdoxsey)
- authorize: implement allowed\_idp\_claims [\#1542](https://github.com/pomerium/pomerium/pull/1542) (@calebdoxsey)
- autocert: support certificate renewal [\#1516](https://github.com/pomerium/pomerium/pull/1516) (@calebdoxsey)
- add policy to allow any authenticated user [\#1515](https://github.com/pomerium/pomerium/pull/1515) (@pflipp)
- debug: add pprof endpoints [\#1504](https://github.com/pomerium/pomerium/pull/1504) (@calebdoxsey)
- databroker: require JWT for access [\#1503](https://github.com/pomerium/pomerium/pull/1503) (@calebdoxsey)
- authenticate: remove unused paths, generate cipher at startup, remove qp store [\#1495](https://github.com/pomerium/pomerium/pull/1495) (@desimone)
- forward-auth: use envoy's ext\_authz check [\#1482](https://github.com/pomerium/pomerium/pull/1482) (@desimone)
- auth0: implement directory provider [\#1479](https://github.com/pomerium/pomerium/pull/1479) (@grounded042)
- azure: incremental sync [\#1471](https://github.com/pomerium/pomerium/pull/1471) (@calebdoxsey)
- auth0: implement identity provider [\#1470](https://github.com/pomerium/pomerium/pull/1470) (@calebdoxsey)
- dashboard: format timestamps [\#1468](https://github.com/pomerium/pomerium/pull/1468) (@calebdoxsey)
- directory: additional user info [\#1467](https://github.com/pomerium/pomerium/pull/1467) (@calebdoxsey)
- directory: add explicit RefreshUser endpoint for faster sync [\#1460](https://github.com/pomerium/pomerium/pull/1460) (@calebdoxsey)
- config: add support for host header rewriting [\#1457](https://github.com/pomerium/pomerium/pull/1457) (@calebdoxsey)
- proxy: preserve path and query string for http-\>https redirect [\#1456](https://github.com/pomerium/pomerium/pull/1456) (@calebdoxsey)
- redis: use pubsub instead of keyspace events [\#1450](https://github.com/pomerium/pomerium/pull/1450) (@calebdoxsey)
- proxy: add support for /.pomerium/jwt [\#1446](https://github.com/pomerium/pomerium/pull/1446) (@calebdoxsey)
- databroker: add support for querying the databroker [\#1443](https://github.com/pomerium/pomerium/pull/1443) (@calebdoxsey)
- config: add dns\_lookup\_family option to customize DNS IP resolution [\#1436](https://github.com/pomerium/pomerium/pull/1436) (@calebdoxsey)
- okta: handle deleted groups [\#1418](https://github.com/pomerium/pomerium/pull/1418) (@calebdoxsey)
- controlplane: support P-384 / P-512 EC curves [\#1409](https://github.com/pomerium/pomerium/pull/1409) (@desimone)
- azure: add support for nested groups [\#1408](https://github.com/pomerium/pomerium/pull/1408) (@calebdoxsey)
- authorize: add support for service accounts [\#1374](https://github.com/pomerium/pomerium/pull/1374) (@calebdoxsey)
- Cuonglm/improve timeout error message [\#1373](https://github.com/pomerium/pomerium/pull/1373) (@cuonglm)
- internal/directory/okta: remove rate limiter [\#1370](https://github.com/pomerium/pomerium/pull/1370) (@cuonglm)
- {proxy/controlplane}: make health checks debug level [\#1368](https://github.com/pomerium/pomerium/pull/1368) (@desimone)
- databroker: add tracing for rego evaluation and databroker sync, fix bug in databroker config source [\#1367](https://github.com/pomerium/pomerium/pull/1367) (@calebdoxsey)
- authorize: use impersonate email/groups in JWT [\#1364](https://github.com/pomerium/pomerium/pull/1364) (@calebdoxsey)
- config: support explicit prefix and regex path rewriting [\#1363](https://github.com/pomerium/pomerium/pull/1363) (@calebdoxsey)
- proxy: support websocket timeouts [\#1362](https://github.com/pomerium/pomerium/pull/1362) (@calebdoxsey)
- proxy: disable control-plane robots.txt for public unauthenticated routes [\#1361](https://github.com/pomerium/pomerium/pull/1361) (@calebdoxsey)
- certmagic: improve logging [\#1358](https://github.com/pomerium/pomerium/pull/1358) (@calebdoxsey)
- logs: add new log scrubber [\#1346](https://github.com/pomerium/pomerium/pull/1346) (@calebdoxsey)
- Allow setting the shared secret via an environment variable. [\#1337](https://github.com/pomerium/pomerium/pull/1337) (@rspier)
- authorize: add jti to JWT payload [\#1328](https://github.com/pomerium/pomerium/pull/1328) (@calebdoxsey)
- all: add signout redirect url [\#1324](https://github.com/pomerium/pomerium/pull/1324) (@cuonglm)
- proxy: remove unused handlers [\#1317](https://github.com/pomerium/pomerium/pull/1317) (@desimone)
- azure: support deriving credentials from client id, client secret and provider url [\#1300](https://github.com/pomerium/pomerium/pull/1300) (@calebdoxsey)
- cache: support databroker option changes [\#1294](https://github.com/pomerium/pomerium/pull/1294) (@calebdoxsey)
- authenticate: move databroker connection to state [\#1292](https://github.com/pomerium/pomerium/pull/1292) (@calebdoxsey)
- authorize: use atomic state for properties [\#1290](https://github.com/pomerium/pomerium/pull/1290) (@calebdoxsey)
- proxy: move properties to atomically updated state [\#1280](https://github.com/pomerium/pomerium/pull/1280) (@calebdoxsey)
- Improving okta API requests [\#1278](https://github.com/pomerium/pomerium/pull/1278) (@cuonglm)
- authenticate: move properties to atomically updated state [\#1277](https://github.com/pomerium/pomerium/pull/1277) (@calebdoxsey)
- authenticate: support reloading IDP settings [\#1273](https://github.com/pomerium/pomerium/pull/1273) (@calebdoxsey)
- Rate limit for okta [\#1271](https://github.com/pomerium/pomerium/pull/1271) (@cuonglm)
- config: allow dynamic configuration of cookie settings [\#1267](https://github.com/pomerium/pomerium/pull/1267) (@calebdoxsey)
- internal/directory/okta: increase default batch size to 200 [\#1264](https://github.com/pomerium/pomerium/pull/1264) (@cuonglm)
- envoy: add support for hot-reloading bootstrap configuration [\#1259](https://github.com/pomerium/pomerium/pull/1259) (@calebdoxsey)
- config: allow reloading of telemetry settings [\#1255](https://github.com/pomerium/pomerium/pull/1255) (@calebdoxsey)
- databroker: add support for config settings [\#1253](https://github.com/pomerium/pomerium/pull/1253) (@calebdoxsey)
- config: warn if custom scopes set for builtin providers [\#1252](https://github.com/pomerium/pomerium/pull/1252) (@cuonglm)
- authorize: add databroker url check [\#1228](https://github.com/pomerium/pomerium/pull/1228) (@desimone)
- internal/databroker: make Sync send data in smaller batches [\#1226](https://github.com/pomerium/pomerium/pull/1226) (@cuonglm)

## Fixed

- fix config race [\#1660](https://github.com/pomerium/pomerium/pull/1660) (@calebdoxsey)
- fix ordering of autocert config source [\#1640](https://github.com/pomerium/pomerium/pull/1640) (@calebdoxsey)
- pkg/storage/redis: Prevent connection churn [\#1603](https://github.com/pomerium/pomerium/pull/1603) (@travisgroth)
-  forward-auth: fix special character support for nginx  [\#1578](https://github.com/pomerium/pomerium/pull/1578) (@desimone)
- proxy/forward\_auth: copy response headers as request headers [\#1577](https://github.com/pomerium/pomerium/pull/1577) (@desimone)
- fix querying claim data on the dashboard [\#1560](https://github.com/pomerium/pomerium/pull/1560) (@calebdoxsey)
- github: fix retrieving team id with graphql API \(\#1554\) [\#1555](https://github.com/pomerium/pomerium/pull/1555) (@toshipp)
- store raw id token so it can be passed to the logout url [\#1543](https://github.com/pomerium/pomerium/pull/1543) (@calebdoxsey)
- fix databroker requiring signed jwt [\#1538](https://github.com/pomerium/pomerium/pull/1538) (@calebdoxsey)
- authorize: add redirect url to debug page [\#1533](https://github.com/pomerium/pomerium/pull/1533) (@desimone)
- internal/frontend: resolve authN helper url [\#1521](https://github.com/pomerium/pomerium/pull/1521) (@desimone)
- fwd-auth: match nginx-ingress config [\#1505](https://github.com/pomerium/pomerium/pull/1505) (@desimone)
- authenticate: protect /.pomerium/admin endpoint [\#1500](https://github.com/pomerium/pomerium/pull/1500) (@calebdoxsey)
- ci: ensure systemd unit file is in packages [\#1481](https://github.com/pomerium/pomerium/pull/1481) (@travisgroth)
- identity manager: fix directory sync timing [\#1455](https://github.com/pomerium/pomerium/pull/1455) (@calebdoxsey)
- proxy/forward\_auth: don't reset forward auth path if X-Forwarded-Uri is not set [\#1447](https://github.com/pomerium/pomerium/pull/1447) (@whs)
- httputil: remove retry button [\#1438](https://github.com/pomerium/pomerium/pull/1438) (@desimone)
- proxy: always use https for application callback [\#1433](https://github.com/pomerium/pomerium/pull/1433) (@travisgroth)
- controplane: remove p-521 EC [\#1420](https://github.com/pomerium/pomerium/pull/1420) (@desimone)
- redirect-server: add config headers to responses [\#1416](https://github.com/pomerium/pomerium/pull/1416) (@calebdoxsey)
- proxy: remove impersonate headers for kubernetes [\#1394](https://github.com/pomerium/pomerium/pull/1394) (@calebdoxsey)
- Desimone/authenticate default logout [\#1390](https://github.com/pomerium/pomerium/pull/1390) (@desimone)
- proxy: for filter matches only include bare domain name [\#1389](https://github.com/pomerium/pomerium/pull/1389) (@calebdoxsey)
- internal/envoy: start epoch from 0 [\#1387](https://github.com/pomerium/pomerium/pull/1387) (@travisgroth)
- internal/directory/okta: acceept non-json service account [\#1359](https://github.com/pomerium/pomerium/pull/1359) (@cuonglm)
- internal/controlplane: add telemetry http handler [\#1353](https://github.com/pomerium/pomerium/pull/1353) (@travisgroth)
- autocert: fix locking issue [\#1310](https://github.com/pomerium/pomerium/pull/1310) (@calebdoxsey)
- authorize: log users and groups [\#1303](https://github.com/pomerium/pomerium/pull/1303) (@desimone)
- proxy: fix wrong applied middleware [\#1298](https://github.com/pomerium/pomerium/pull/1298) (@cuonglm)
- internal/directory/okta: fix wrong API query filter [\#1296](https://github.com/pomerium/pomerium/pull/1296) (@cuonglm)
- autocert: fix  bootstrapped cache store path [\#1283](https://github.com/pomerium/pomerium/pull/1283) (@desimone)
- config: validate databroker settings [\#1260](https://github.com/pomerium/pomerium/pull/1260) (@calebdoxsey)
- internal/autocert: re-use cert if renewing failed but cert not expired [\#1237](https://github.com/pomerium/pomerium/pull/1237) (@cuonglm)

## Security

- chore\(deps\): update envoy 1.16.1 [\#1613](https://github.com/pomerium/pomerium/pull/1613) (@desimone)

## Documentation

- move signing key algorithm documentation into yaml file [\#1646](https://github.com/pomerium/pomerium/pull/1646) (@calebdoxsey)
- update docs [\#1645](https://github.com/pomerium/pomerium/pull/1645) (@desimone)
- docs: update build badge [\#1635](https://github.com/pomerium/pomerium/pull/1635) (@travisgroth)
- docs: add cache\_service\_url upgrade notice [\#1621](https://github.com/pomerium/pomerium/pull/1621) (@travisgroth)
- docs: use standard language for lists [\#1590](https://github.com/pomerium/pomerium/pull/1590) (@desimone)
- Fix command in Kubernetes Quick start docs [\#1582](https://github.com/pomerium/pomerium/pull/1582) (@wesleyw72)
- move docs to settings.yaml [\#1579](https://github.com/pomerium/pomerium/pull/1579) (@calebdoxsey)
- docs: add round logo [\#1574](https://github.com/pomerium/pomerium/pull/1574) (@desimone)
- add settings.yaml file [\#1540](https://github.com/pomerium/pomerium/pull/1540) (@calebdoxsey)
- update the documentation for auth0 to include group/role information [\#1502](https://github.com/pomerium/pomerium/pull/1502) (@grounded042)
- examples: fix nginx example [\#1478](https://github.com/pomerium/pomerium/pull/1478) (@desimone)
- docs: add architecture diagram for cloudrun [\#1444](https://github.com/pomerium/pomerium/pull/1444) (@travisgroth)
- fix\(examples\): Use X-Pomerium-Claim headers [\#1422](https://github.com/pomerium/pomerium/pull/1422) (@tdorsey)
- chore\(docs\): Fix typo in example policy [\#1419](https://github.com/pomerium/pomerium/pull/1419) (@tdorsey)
- docs: fix grammar [\#1412](https://github.com/pomerium/pomerium/pull/1412) (@shinebayar-g)
- docs: Add Traefik + Kubernetes example [\#1411](https://github.com/pomerium/pomerium/pull/1411) (@travisgroth)
- Remove typo on remove\_request\_headers docs [\#1388](https://github.com/pomerium/pomerium/pull/1388) (@whs)
- docs: update azure docs [\#1377](https://github.com/pomerium/pomerium/pull/1377) (@desimone)
- docs: add nginx example [\#1329](https://github.com/pomerium/pomerium/pull/1329) (@travisgroth)
- docs: use .com sitemap hostname [\#1274](https://github.com/pomerium/pomerium/pull/1274) (@desimone)
- docs: fix in-action video [\#1268](https://github.com/pomerium/pomerium/pull/1268) (@travisgroth)
- docs: image, sitemap and redirect fixes [\#1263](https://github.com/pomerium/pomerium/pull/1263) (@travisgroth)
- Fix broken logo link in README.md [\#1261](https://github.com/pomerium/pomerium/pull/1261) (@cuonglm)
- docs/docs: fix wrong okta service account field [\#1251](https://github.com/pomerium/pomerium/pull/1251) (@cuonglm)
- \[Backport latest\] Docs/enterprise button [\#1247](https://github.com/pomerium/pomerium/pull/1247) (@github-actions[bot])
- Docs/enterprise button [\#1245](https://github.com/pomerium/pomerium/pull/1245) (@desimone)
- remove rootDomain from examples [\#1244](https://github.com/pomerium/pomerium/pull/1244) (@karelbilek)
- docs: add / redirect [\#1241](https://github.com/pomerium/pomerium/pull/1241) (@desimone)
- docs: prepare for enterprise / oss split [\#1238](https://github.com/pomerium/pomerium/pull/1238) (@desimone)

## Dependency

- chore\(deps\): update module open-policy-agent/opa to v0.25.1 [\#1659](https://github.com/pomerium/pomerium/pull/1659) (@renovate[bot])
- chore\(deps\): update module lithammer/shortuuid/v3 to v3.0.5 [\#1658](https://github.com/pomerium/pomerium/pull/1658) (@renovate[bot])
- chore\(deps\): update module google.golang.org/grpc to v1.34.0 [\#1657](https://github.com/pomerium/pomerium/pull/1657) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 9ee31aa [\#1655](https://github.com/pomerium/pomerium/pull/1655) (@renovate[bot])
- chore\(deps\): update golang.org/x/oauth2 commit hash to 9317641 [\#1654](https://github.com/pomerium/pomerium/pull/1654) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to c7110b5 [\#1653](https://github.com/pomerium/pomerium/pull/1653) (@renovate[bot])
- chore\(deps\): update golang.org/x/crypto commit hash to be400ae [\#1652](https://github.com/pomerium/pomerium/pull/1652) (@renovate[bot])
- deps: update hashstructure v2 [\#1632](https://github.com/pomerium/pomerium/pull/1632) (@desimone)
- chore\(deps\): update precommit hook pre-commit/pre-commit-hooks to v3 [\#1630](https://github.com/pomerium/pomerium/pull/1630) (@renovate[bot])
- chore\(deps\): update module yaml to v2.4.0 [\#1629](https://github.com/pomerium/pomerium/pull/1629) (@renovate[bot])
- chore\(deps\): update module google/go-cmp to v0.5.4 [\#1628](https://github.com/pomerium/pomerium/pull/1628) (@renovate[bot])
- chore\(deps\): update golang.org/x/crypto commit hash to c8d3bf9 [\#1627](https://github.com/pomerium/pomerium/pull/1627) (@renovate[bot])
- chore\(deps\): update module google/go-jsonnet to v0.17.0 [\#1611](https://github.com/pomerium/pomerium/pull/1611) (@renovate[bot])
- chore\(deps\): update codecov/codecov-action action to v1.0.15 [\#1610](https://github.com/pomerium/pomerium/pull/1610) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 9b1e624 [\#1609](https://github.com/pomerium/pomerium/pull/1609) (@renovate[bot])
- chore\(deps\): update golang.org/x/crypto commit hash to c1f2f97 [\#1608](https://github.com/pomerium/pomerium/pull/1608) (@renovate[bot])
- chore\(deps\): update module google/go-cmp to v0.5.3 [\#1597](https://github.com/pomerium/pomerium/pull/1597) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to ce600e9 [\#1596](https://github.com/pomerium/pomerium/pull/1596) (@renovate[bot])
- chore\(deps\): update golang.org/x/oauth2 commit hash to 9fd6049 [\#1595](https://github.com/pomerium/pomerium/pull/1595) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to 69a7880 [\#1594](https://github.com/pomerium/pomerium/pull/1594) (@renovate[bot])
- chore\(deps\): update golang.org/x/crypto commit hash to 0c6587e [\#1593](https://github.com/pomerium/pomerium/pull/1593) (@renovate[bot])
- chore\(deps\): update module google.golang.org/grpc to v1.33.2 [\#1585](https://github.com/pomerium/pomerium/pull/1585) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to f9bfe23 [\#1583](https://github.com/pomerium/pomerium/pull/1583) (@renovate[bot])
- chore\(deps\): update mikefarah/yq action to v3.4.1 [\#1567](https://github.com/pomerium/pomerium/pull/1567) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 24207fd [\#1566](https://github.com/pomerium/pomerium/pull/1566) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to ff519b6 [\#1565](https://github.com/pomerium/pomerium/pull/1565) (@renovate[bot])
- chore\(deps\): update olegtarasov/get-tag action to v2 [\#1552](https://github.com/pomerium/pomerium/pull/1552) (@renovate[bot])
- chore\(deps\): update goreleaser/goreleaser-action action to v2 [\#1551](https://github.com/pomerium/pomerium/pull/1551) (@renovate[bot])
- chore\(deps\): update actions/setup-go action to v2 [\#1550](https://github.com/pomerium/pomerium/pull/1550) (@renovate[bot])
- chore\(deps\): update toolmantim/release-drafter action to v5.12.1 [\#1549](https://github.com/pomerium/pomerium/pull/1549) (@renovate[bot])
- chore\(deps\): update module google.golang.org/grpc to v1.33.1 [\#1548](https://github.com/pomerium/pomerium/pull/1548) (@renovate[bot])
- chore\(deps\): update codecov/codecov-action action to v1.0.14 [\#1547](https://github.com/pomerium/pomerium/pull/1547) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 0ff5f38 [\#1546](https://github.com/pomerium/pomerium/pull/1546) (@renovate[bot])
- chore\(deps\): update golang.org/x/sync commit hash to 67f06af [\#1545](https://github.com/pomerium/pomerium/pull/1545) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to be3efd7 [\#1544](https://github.com/pomerium/pomerium/pull/1544) (@renovate[bot])
- chore\(deps\): update vuepress monorepo to v1.7.1 [\#1531](https://github.com/pomerium/pomerium/pull/1531) (@renovate[bot])
- chore\(deps\): update module spf13/cobra to v1.1.1 [\#1530](https://github.com/pomerium/pomerium/pull/1530) (@renovate[bot])
- chore\(deps\): update module prometheus/client\_golang to v1.8.0 [\#1529](https://github.com/pomerium/pomerium/pull/1529) (@renovate[bot])
- chore\(deps\): update module ory/dockertest/v3 to v3.6.2 [\#1528](https://github.com/pomerium/pomerium/pull/1528) (@renovate[bot])
- chore\(deps\): update module open-policy-agent/opa to v0.24.0 [\#1527](https://github.com/pomerium/pomerium/pull/1527) (@renovate[bot])
- chore\(deps\): update module golang/protobuf to v1.4.3 [\#1525](https://github.com/pomerium/pomerium/pull/1525) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 32ed001 [\#1524](https://github.com/pomerium/pomerium/pull/1524) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to 7b1cca2 [\#1523](https://github.com/pomerium/pomerium/pull/1523) (@renovate[bot])
- chore\(deps\): update golang.org/x/crypto commit hash to 9e8e0b3 [\#1522](https://github.com/pomerium/pomerium/pull/1522) (@renovate[bot])
- chore\(deps\): upgrade envoy to v0.16.0 [\#1519](https://github.com/pomerium/pomerium/pull/1519) (@desimone)
- deployment: run go mod tidy [\#1512](https://github.com/pomerium/pomerium/pull/1512) (@desimone)
- chore\(deps\): update module ory/dockertest/v3 to v3.6.1 [\#1511](https://github.com/pomerium/pomerium/pull/1511) (@renovate[bot])
- chore\(deps\): update module go.opencensus.io to v0.22.5 [\#1510](https://github.com/pomerium/pomerium/pull/1510) (@renovate[bot])
- chore\(deps\): update module cenkalti/backoff/v4 to v4.1.0 [\#1509](https://github.com/pomerium/pomerium/pull/1509) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 4d944d3 [\#1508](https://github.com/pomerium/pomerium/pull/1508) (@renovate[bot])
- chore\(deps\): update golang.org/x/sync commit hash to b3e1573 [\#1507](https://github.com/pomerium/pomerium/pull/1507) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to 4f7140c [\#1506](https://github.com/pomerium/pomerium/pull/1506) (@renovate[bot])
- deployment: pin /x/sys to fix dockertest [\#1491](https://github.com/pomerium/pomerium/pull/1491) (@desimone)
- chore\(deps\): update module openzipkin/zipkin-go to v0.2.5 [\#1488](https://github.com/pomerium/pomerium/pull/1488) (@renovate[bot])
- chore\(deps\): update module envoyproxy/go-control-plane to v0.9.7 [\#1487](https://github.com/pomerium/pomerium/pull/1487) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to bcad7cf [\#1486](https://github.com/pomerium/pomerium/pull/1486) (@renovate[bot])
- chore\(deps\): update golang.org/x/sync commit hash to 3042136 [\#1485](https://github.com/pomerium/pomerium/pull/1485) (@renovate[bot])
- chore\(deps\): update golang.org/x/crypto commit hash to 7f63de1 [\#1483](https://github.com/pomerium/pomerium/pull/1483) (@renovate[bot])
- deps: update envoy arm64 to v1.15.1 [\#1475](https://github.com/pomerium/pomerium/pull/1475) (@travisgroth)
- chore\(deps\): envoy 1.15.1 [\#1473](https://github.com/pomerium/pomerium/pull/1473) (@desimone)
- chore\(deps\): update vuepress monorepo to v1.6.0 [\#1463](https://github.com/pomerium/pomerium/pull/1463) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to c2d885f [\#1462](https://github.com/pomerium/pomerium/pull/1462) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to 5d4f700 [\#1461](https://github.com/pomerium/pomerium/pull/1461) (@renovate[bot])
- deps: go mod tidy [\#1434](https://github.com/pomerium/pomerium/pull/1434) (@travisgroth)
- chore\(deps\): update module rs/zerolog to v1.20.0 [\#1431](https://github.com/pomerium/pomerium/pull/1431) (@renovate[bot])
- chore\(deps\): update module caddyserver/certmagic to v0.12.0 [\#1429](https://github.com/pomerium/pomerium/pull/1429) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to d0d6055 [\#1428](https://github.com/pomerium/pomerium/pull/1428) (@renovate[bot])
- chore\(deps\): update module openzipkin/zipkin-go to v0.2.4 [\#1407](https://github.com/pomerium/pomerium/pull/1407) (@renovate[bot])
- chore\(deps\): update module gorilla/handlers to v1.5.1 [\#1406](https://github.com/pomerium/pomerium/pull/1406) (@renovate[bot])
- chore\(deps\): update module google.golang.org/grpc to v1.32.0 [\#1405](https://github.com/pomerium/pomerium/pull/1405) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 645f7a4 [\#1404](https://github.com/pomerium/pomerium/pull/1404) (@renovate[bot])
- Run go mod tidy [\#1384](https://github.com/pomerium/pomerium/pull/1384) (@cuonglm)
- chore\(deps\): update module go.uber.org/zap to v1.16.0 [\#1381](https://github.com/pomerium/pomerium/pull/1381) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 0bd0a95 [\#1380](https://github.com/pomerium/pomerium/pull/1380) (@renovate[bot])
- chore\(deps\): update golang.org/x/oauth2 commit hash to 5d25da1 [\#1379](https://github.com/pomerium/pomerium/pull/1379) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to 62affa3 [\#1378](https://github.com/pomerium/pomerium/pull/1378) (@renovate[bot])
- deps: ensure renovate runs `go mod tidy` [\#1357](https://github.com/pomerium/pomerium/pull/1357) (@travisgroth)
- deps: go mod tidy [\#1356](https://github.com/pomerium/pomerium/pull/1356) (@travisgroth)
- Update module open-policy-agent/opa to v0.23.2 [\#1351](https://github.com/pomerium/pomerium/pull/1351) (@renovate[bot])
- Update module google/uuid to v1.1.2 [\#1350](https://github.com/pomerium/pomerium/pull/1350) (@renovate[bot])
- Update module google/go-cmp to v0.5.2 [\#1349](https://github.com/pomerium/pomerium/pull/1349) (@renovate[bot])
- Update module google.golang.org/grpc to v1.31.1 [\#1348](https://github.com/pomerium/pomerium/pull/1348) (@renovate[bot])
- Update google.golang.org/genproto commit hash to 2bf3329 [\#1347](https://github.com/pomerium/pomerium/pull/1347) (@renovate[bot])
- chore\(deps\): update vuepress monorepo to v1.5.4 [\#1323](https://github.com/pomerium/pomerium/pull/1323) (@renovate[bot])
- chore\(deps\): update module open-policy-agent/opa to v0.23.1 [\#1322](https://github.com/pomerium/pomerium/pull/1322) (@renovate[bot])
- chore\(deps\): update module gorilla/mux to v1.8.0 [\#1321](https://github.com/pomerium/pomerium/pull/1321) (@renovate[bot])
- chore\(deps\): update module gorilla/handlers to v1.5.0 [\#1320](https://github.com/pomerium/pomerium/pull/1320) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to c890458 [\#1319](https://github.com/pomerium/pomerium/pull/1319) (@renovate[bot])
- chore\(deps\): update golang.org/x/crypto commit hash to 5c72a88 [\#1318](https://github.com/pomerium/pomerium/pull/1318) (@renovate[bot])
- Upgrade zipkin-go to v0.2.3 [\#1288](https://github.com/pomerium/pomerium/pull/1288) (@cuonglm)
- chore\(deps\): update google.golang.org/genproto commit hash to f69a880 [\#1286](https://github.com/pomerium/pomerium/pull/1286) (@renovate[bot])
- chore\(deps\): update golang.org/x/time commit hash to 3af7569 [\#1285](https://github.com/pomerium/pomerium/pull/1285) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to 3edf25e [\#1284](https://github.com/pomerium/pomerium/pull/1284) (@renovate[bot])
- .github/workflows: upgrade to go1.15 [\#1258](https://github.com/pomerium/pomerium/pull/1258) (@cuonglm)
- Fix tests failed with go115 [\#1257](https://github.com/pomerium/pomerium/pull/1257) (@cuonglm)
- chore\(deps\): update dependency @vuepress/plugin-google-analytics to v1.5.3 [\#1236](https://github.com/pomerium/pomerium/pull/1236) (@renovate[bot])
- Update module google.golang.org/api to v0.30.0 [\#1235](https://github.com/pomerium/pomerium/pull/1235) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to a062522 [\#1234](https://github.com/pomerium/pomerium/pull/1234) (@renovate[bot])

## Deployment

- deployment: enable multi-arch release images [\#1643](https://github.com/pomerium/pomerium/pull/1643) (@travisgroth)
- ci: add bintray publishing [\#1618](https://github.com/pomerium/pomerium/pull/1618) (@travisgroth)
- ci: remove bad quoting in publish steps [\#1617](https://github.com/pomerium/pomerium/pull/1617) (@travisgroth)
- ci: update tag parsing step [\#1616](https://github.com/pomerium/pomerium/pull/1616) (@travisgroth)
- remove memberlist [\#1615](https://github.com/pomerium/pomerium/pull/1615) (@calebdoxsey)
- ci: automatically update test environment with master [\#1562](https://github.com/pomerium/pomerium/pull/1562) (@travisgroth)
- deployment: add debug build / container / docs [\#1513](https://github.com/pomerium/pomerium/pull/1513) (@travisgroth)
- deployment: Generate deb and rpm packages [\#1458](https://github.com/pomerium/pomerium/pull/1458) (@travisgroth)
- deployment: bump release go to v1.15.x [\#1439](https://github.com/pomerium/pomerium/pull/1439) (@desimone)
- ci: publish cloudrun latest tag [\#1398](https://github.com/pomerium/pomerium/pull/1398) (@travisgroth)
- deployment: fully split release archives and brews [\#1365](https://github.com/pomerium/pomerium/pull/1365) (@travisgroth)
- Include pomerium-cli in the docker image by default.  Fixes \#1343. [\#1345](https://github.com/pomerium/pomerium/pull/1345) (@rspier)
- Use apt-get instead of apt to eliminate warning. [\#1344](https://github.com/pomerium/pomerium/pull/1344) (@rspier)
- deployment: add goimports with path awareness [\#1316](https://github.com/pomerium/pomerium/pull/1316) (@desimone)

## Changed

- identity/oidc/azure: goimports [\#1651](https://github.com/pomerium/pomerium/pull/1651) (@travisgroth)
- fix panic when deleting a record twice from the inmemory data store [\#1639](https://github.com/pomerium/pomerium/pull/1639) (@calebdoxsey)
- ci: improve release snapshot name template [\#1602](https://github.com/pomerium/pomerium/pull/1602) (@travisgroth)
- ci: fix release workflow syntax [\#1592](https://github.com/pomerium/pomerium/pull/1592) (@travisgroth)
- ci: update changelog generation to script [\#1589](https://github.com/pomerium/pomerium/pull/1589) (@travisgroth)
- \[Backport 0-10-0\] docs: add round logo [\#1575](https://github.com/pomerium/pomerium/pull/1575) (@github-actions[bot])
- tidy [\#1494](https://github.com/pomerium/pomerium/pull/1494) (@desimone)
- dev: add remote container debug configs [\#1459](https://github.com/pomerium/pomerium/pull/1459) (@desimone)
- ci: add stale issue automation [\#1366](https://github.com/pomerium/pomerium/pull/1366) (@travisgroth)
- internal/urlutil: remove un-used constants [\#1326](https://github.com/pomerium/pomerium/pull/1326) (@cuonglm)
- integration: add forward auth test [\#1312](https://github.com/pomerium/pomerium/pull/1312) (@cuonglm)
- pkg/storage/redis: update tests to use local certs + upstream image [\#1306](https://github.com/pomerium/pomerium/pull/1306) (@travisgroth)
- config: omit empty subpolicies in yaml/json [\#1229](https://github.com/pomerium/pomerium/pull/1229) (@travisgroth)
- Cuonglm/increase coverrage 1 [\#1227](https://github.com/pomerium/pomerium/pull/1227) (@cuonglm)

## [v0.11.0-rc2](https://github.com/pomerium/pomerium/tree/v0.11.0-rc2) (2020-11-19)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.11.0-rc1...v0.11.0-rc2)

## New

- add paging support to GetAll [\#1601](https://github.com/pomerium/pomerium/pull/1601) (@calebdoxsey)
- attach version to gRPC server metadata [\#1598](https://github.com/pomerium/pomerium/pull/1598) (@calebdoxsey)

## Fixed

- pkg/storage/redis: Prevent connection churn [\#1603](https://github.com/pomerium/pomerium/pull/1603) (@travisgroth)

## Dependency

- chore\(deps\): update module google/go-cmp to v0.5.3 [\#1597](https://github.com/pomerium/pomerium/pull/1597) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to ce600e9 [\#1596](https://github.com/pomerium/pomerium/pull/1596) (@renovate[bot])
- chore\(deps\): update golang.org/x/oauth2 commit hash to 9fd6049 [\#1595](https://github.com/pomerium/pomerium/pull/1595) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to 69a7880 [\#1594](https://github.com/pomerium/pomerium/pull/1594) (@renovate[bot])
- chore\(deps\): update golang.org/x/crypto commit hash to 0c6587e [\#1593](https://github.com/pomerium/pomerium/pull/1593) (@renovate[bot])

## Changed

- ci: improve release snapshot name template [\#1602](https://github.com/pomerium/pomerium/pull/1602) (@travisgroth)

## [v0.11.0-rc1](https://github.com/pomerium/pomerium/tree/v0.11.0-rc1) (2020-11-13)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.10.6...v0.11.0-rc1)

## Breaking

- add flag to enable user impersonation [\#1514](https://github.com/pomerium/pomerium/pull/1514) (@calebdoxsey)

## New

- use custom default http transport [\#1576](https://github.com/pomerium/pomerium/pull/1576) (@calebdoxsey)
- update user info in addition to refreshing the token [\#1572](https://github.com/pomerium/pomerium/pull/1572) (@calebdoxsey)
- databroker: add audience to session [\#1557](https://github.com/pomerium/pomerium/pull/1557) (@calebdoxsey)
- authorize: implement allowed\_idp\_claims [\#1542](https://github.com/pomerium/pomerium/pull/1542) (@calebdoxsey)
- autocert: support certificate renewal [\#1516](https://github.com/pomerium/pomerium/pull/1516) (@calebdoxsey)
- add policy to allow any authenticated user [\#1515](https://github.com/pomerium/pomerium/pull/1515) (@pflipp)
- debug: add pprof endpoints [\#1504](https://github.com/pomerium/pomerium/pull/1504) (@calebdoxsey)
- databroker: require JWT for access [\#1503](https://github.com/pomerium/pomerium/pull/1503) (@calebdoxsey)
- authenticate: remove unused paths, generate cipher at startup, remove qp store [\#1495](https://github.com/pomerium/pomerium/pull/1495) (@desimone)
- forward-auth: use envoy's ext\_authz check [\#1482](https://github.com/pomerium/pomerium/pull/1482) (@desimone)
- auth0: implement directory provider [\#1479](https://github.com/pomerium/pomerium/pull/1479) (@grounded042)
- azure: incremental sync [\#1471](https://github.com/pomerium/pomerium/pull/1471) (@calebdoxsey)
- auth0: implement identity provider [\#1470](https://github.com/pomerium/pomerium/pull/1470) (@calebdoxsey)
- dashboard: format timestamps [\#1468](https://github.com/pomerium/pomerium/pull/1468) (@calebdoxsey)
- directory: additional user info [\#1467](https://github.com/pomerium/pomerium/pull/1467) (@calebdoxsey)
- directory: add explicit RefreshUser endpoint for faster sync [\#1460](https://github.com/pomerium/pomerium/pull/1460) (@calebdoxsey)
- config: add support for host header rewriting [\#1457](https://github.com/pomerium/pomerium/pull/1457) (@calebdoxsey)
- proxy: preserve path and query string for http-\>https redirect [\#1456](https://github.com/pomerium/pomerium/pull/1456) (@calebdoxsey)
- redis: use pubsub instead of keyspace events [\#1450](https://github.com/pomerium/pomerium/pull/1450) (@calebdoxsey)
- proxy: add support for /.pomerium/jwt [\#1446](https://github.com/pomerium/pomerium/pull/1446) (@calebdoxsey)
- databroker: add support for querying the databroker [\#1443](https://github.com/pomerium/pomerium/pull/1443) (@calebdoxsey)
- config: add dns\_lookup\_family option to customize DNS IP resolution [\#1436](https://github.com/pomerium/pomerium/pull/1436) (@calebdoxsey)
- okta: handle deleted groups [\#1418](https://github.com/pomerium/pomerium/pull/1418) (@calebdoxsey)
- controlplane: support P-384 / P-512 EC curves [\#1409](https://github.com/pomerium/pomerium/pull/1409) (@desimone)
- azure: add support for nested groups [\#1408](https://github.com/pomerium/pomerium/pull/1408) (@calebdoxsey)
- authorize: add support for service accounts [\#1374](https://github.com/pomerium/pomerium/pull/1374) (@calebdoxsey)
- Cuonglm/improve timeout error message [\#1373](https://github.com/pomerium/pomerium/pull/1373) (@cuonglm)
- internal/directory/okta: remove rate limiter [\#1370](https://github.com/pomerium/pomerium/pull/1370) (@cuonglm)
- {proxy/controlplane}: make health checks debug level [\#1368](https://github.com/pomerium/pomerium/pull/1368) (@desimone)
- databroker: add tracing for rego evaluation and databroker sync, fix bug in databroker config source [\#1367](https://github.com/pomerium/pomerium/pull/1367) (@calebdoxsey)
- authorize: use impersonate email/groups in JWT [\#1364](https://github.com/pomerium/pomerium/pull/1364) (@calebdoxsey)
- config: support explicit prefix and regex path rewriting [\#1363](https://github.com/pomerium/pomerium/pull/1363) (@calebdoxsey)
- proxy: support websocket timeouts [\#1362](https://github.com/pomerium/pomerium/pull/1362) (@calebdoxsey)
- proxy: disable control-plane robots.txt for public unauthenticated routes [\#1361](https://github.com/pomerium/pomerium/pull/1361) (@calebdoxsey)
- certmagic: improve logging [\#1358](https://github.com/pomerium/pomerium/pull/1358) (@calebdoxsey)
- logs: add new log scrubber [\#1346](https://github.com/pomerium/pomerium/pull/1346) (@calebdoxsey)
- Allow setting the shared secret via an environment variable. [\#1337](https://github.com/pomerium/pomerium/pull/1337) (@rspier)
- authorize: add jti to JWT payload [\#1328](https://github.com/pomerium/pomerium/pull/1328) (@calebdoxsey)
- all: add signout redirect url [\#1324](https://github.com/pomerium/pomerium/pull/1324) (@cuonglm)
- proxy: remove unused handlers [\#1317](https://github.com/pomerium/pomerium/pull/1317) (@desimone)
- azure: support deriving credentials from client id, client secret and provider url [\#1300](https://github.com/pomerium/pomerium/pull/1300) (@calebdoxsey)
- cache: support databroker option changes [\#1294](https://github.com/pomerium/pomerium/pull/1294) (@calebdoxsey)
- authenticate: move databroker connection to state [\#1292](https://github.com/pomerium/pomerium/pull/1292) (@calebdoxsey)
- authorize: use atomic state for properties [\#1290](https://github.com/pomerium/pomerium/pull/1290) (@calebdoxsey)
- proxy: move properties to atomically updated state [\#1280](https://github.com/pomerium/pomerium/pull/1280) (@calebdoxsey)
- Improving okta API requests [\#1278](https://github.com/pomerium/pomerium/pull/1278) (@cuonglm)
- authenticate: move properties to atomically updated state [\#1277](https://github.com/pomerium/pomerium/pull/1277) (@calebdoxsey)
- authenticate: support reloading IDP settings [\#1273](https://github.com/pomerium/pomerium/pull/1273) (@calebdoxsey)
- Rate limit for okta [\#1271](https://github.com/pomerium/pomerium/pull/1271) (@cuonglm)
- config: allow dynamic configuration of cookie settings [\#1267](https://github.com/pomerium/pomerium/pull/1267) (@calebdoxsey)
- internal/directory/okta: increase default batch size to 200 [\#1264](https://github.com/pomerium/pomerium/pull/1264) (@cuonglm)
- envoy: add support for hot-reloading bootstrap configuration [\#1259](https://github.com/pomerium/pomerium/pull/1259) (@calebdoxsey)
- config: allow reloading of telemetry settings [\#1255](https://github.com/pomerium/pomerium/pull/1255) (@calebdoxsey)
- databroker: add support for config settings [\#1253](https://github.com/pomerium/pomerium/pull/1253) (@calebdoxsey)
- config: warn if custom scopes set for builtin providers [\#1252](https://github.com/pomerium/pomerium/pull/1252) (@cuonglm)
- authorize: add databroker url check [\#1228](https://github.com/pomerium/pomerium/pull/1228) (@desimone)
- internal/databroker: make Sync send data in smaller batches [\#1226](https://github.com/pomerium/pomerium/pull/1226) (@cuonglm)

## Fixed

-  forward-auth: fix special character support for nginx  [\#1578](https://github.com/pomerium/pomerium/pull/1578) (@desimone)
- proxy/forward\_auth: copy response headers as request headers [\#1577](https://github.com/pomerium/pomerium/pull/1577) (@desimone)
- fix querying claim data on the dashboard [\#1560](https://github.com/pomerium/pomerium/pull/1560) (@calebdoxsey)
- github: fix retrieving team id with graphql API \(\#1554\) [\#1555](https://github.com/pomerium/pomerium/pull/1555) (@toshipp)
- store raw id token so it can be passed to the logout url [\#1543](https://github.com/pomerium/pomerium/pull/1543) (@calebdoxsey)
- fix databroker requiring signed jwt [\#1538](https://github.com/pomerium/pomerium/pull/1538) (@calebdoxsey)
- authorize: add redirect url to debug page [\#1533](https://github.com/pomerium/pomerium/pull/1533) (@desimone)
- internal/frontend: resolve authN helper url [\#1521](https://github.com/pomerium/pomerium/pull/1521) (@desimone)
- fwd-auth: match nginx-ingress config [\#1505](https://github.com/pomerium/pomerium/pull/1505) (@desimone)
- authenticate: protect /.pomerium/admin endpoint [\#1500](https://github.com/pomerium/pomerium/pull/1500) (@calebdoxsey)
- ci: ensure systemd unit file is in packages [\#1481](https://github.com/pomerium/pomerium/pull/1481) (@travisgroth)
- identity manager: fix directory sync timing [\#1455](https://github.com/pomerium/pomerium/pull/1455) (@calebdoxsey)
- proxy/forward\_auth: don't reset forward auth path if X-Forwarded-Uri is not set [\#1447](https://github.com/pomerium/pomerium/pull/1447) (@whs)
- httputil: remove retry button [\#1438](https://github.com/pomerium/pomerium/pull/1438) (@desimone)
- proxy: always use https for application callback [\#1433](https://github.com/pomerium/pomerium/pull/1433) (@travisgroth)
- controplane: remove p-521 EC [\#1420](https://github.com/pomerium/pomerium/pull/1420) (@desimone)
- redirect-server: add config headers to responses [\#1416](https://github.com/pomerium/pomerium/pull/1416) (@calebdoxsey)
- proxy: remove impersonate headers for kubernetes [\#1394](https://github.com/pomerium/pomerium/pull/1394) (@calebdoxsey)
- Desimone/authenticate default logout [\#1390](https://github.com/pomerium/pomerium/pull/1390) (@desimone)
- proxy: for filter matches only include bare domain name [\#1389](https://github.com/pomerium/pomerium/pull/1389) (@calebdoxsey)
- internal/envoy: start epoch from 0 [\#1387](https://github.com/pomerium/pomerium/pull/1387) (@travisgroth)
- internal/directory/okta: acceept non-json service account [\#1359](https://github.com/pomerium/pomerium/pull/1359) (@cuonglm)
- internal/controlplane: add telemetry http handler [\#1353](https://github.com/pomerium/pomerium/pull/1353) (@travisgroth)
- autocert: fix locking issue [\#1310](https://github.com/pomerium/pomerium/pull/1310) (@calebdoxsey)
- authorize: log users and groups [\#1303](https://github.com/pomerium/pomerium/pull/1303) (@desimone)
- proxy: fix wrong applied middleware [\#1298](https://github.com/pomerium/pomerium/pull/1298) (@cuonglm)
- internal/directory/okta: fix wrong API query filter [\#1296](https://github.com/pomerium/pomerium/pull/1296) (@cuonglm)
- autocert: fix  bootstrapped cache store path [\#1283](https://github.com/pomerium/pomerium/pull/1283) (@desimone)
- config: validate databroker settings [\#1260](https://github.com/pomerium/pomerium/pull/1260) (@calebdoxsey)
- internal/autocert: re-use cert if renewing failed but cert not expired [\#1237](https://github.com/pomerium/pomerium/pull/1237) (@cuonglm)

## Documentation

- docs: use standard language for lists [\#1590](https://github.com/pomerium/pomerium/pull/1590) (@desimone)
- Fix command in Kubernetes Quick start docs [\#1582](https://github.com/pomerium/pomerium/pull/1582) (@wesleyw72)
- move docs to settings.yaml [\#1579](https://github.com/pomerium/pomerium/pull/1579) (@calebdoxsey)
- docs: add round logo [\#1574](https://github.com/pomerium/pomerium/pull/1574) (@desimone)
- add settings.yaml file [\#1540](https://github.com/pomerium/pomerium/pull/1540) (@calebdoxsey)
- update the documentation for auth0 to include group/role information [\#1502](https://github.com/pomerium/pomerium/pull/1502) (@grounded042)
- examples: fix nginx example [\#1478](https://github.com/pomerium/pomerium/pull/1478) (@desimone)
- docs: add architecture diagram for cloudrun [\#1444](https://github.com/pomerium/pomerium/pull/1444) (@travisgroth)
- fix\(examples\): Use X-Pomerium-Claim headers [\#1422](https://github.com/pomerium/pomerium/pull/1422) (@tdorsey)
- chore\(docs\): Fix typo in example policy [\#1419](https://github.com/pomerium/pomerium/pull/1419) (@tdorsey)
- docs: fix grammar [\#1412](https://github.com/pomerium/pomerium/pull/1412) (@shinebayar-g)
- docs: Add Traefik + Kubernetes example [\#1411](https://github.com/pomerium/pomerium/pull/1411) (@travisgroth)
- Remove typo on remove\_request\_headers docs [\#1388](https://github.com/pomerium/pomerium/pull/1388) (@whs)
- docs: update azure docs [\#1377](https://github.com/pomerium/pomerium/pull/1377) (@desimone)
- docs: add nginx example [\#1329](https://github.com/pomerium/pomerium/pull/1329) (@travisgroth)
- docs: use .com sitemap hostname [\#1274](https://github.com/pomerium/pomerium/pull/1274) (@desimone)
- docs: fix in-action video [\#1268](https://github.com/pomerium/pomerium/pull/1268) (@travisgroth)
- docs: image, sitemap and redirect fixes [\#1263](https://github.com/pomerium/pomerium/pull/1263) (@travisgroth)
- Fix broken logo link in README.md [\#1261](https://github.com/pomerium/pomerium/pull/1261) (@cuonglm)
- docs/docs: fix wrong okta service account field [\#1251](https://github.com/pomerium/pomerium/pull/1251) (@cuonglm)
- \[Backport latest\] Docs/enterprise button [\#1247](https://github.com/pomerium/pomerium/pull/1247) (@github-actions[bot])
- Docs/enterprise button [\#1245](https://github.com/pomerium/pomerium/pull/1245) (@desimone)
- remove rootDomain from examples [\#1244](https://github.com/pomerium/pomerium/pull/1244) (@karelbilek)
- docs: add / redirect [\#1241](https://github.com/pomerium/pomerium/pull/1241) (@desimone)
- docs: prepare for enterprise / oss split [\#1238](https://github.com/pomerium/pomerium/pull/1238) (@desimone)

## Dependency

- chore\(deps\): update module google.golang.org/grpc to v1.33.2 [\#1585](https://github.com/pomerium/pomerium/pull/1585) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to f9bfe23 [\#1583](https://github.com/pomerium/pomerium/pull/1583) (@renovate[bot])
- chore\(deps\): update mikefarah/yq action to v3.4.1 [\#1567](https://github.com/pomerium/pomerium/pull/1567) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 24207fd [\#1566](https://github.com/pomerium/pomerium/pull/1566) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to ff519b6 [\#1565](https://github.com/pomerium/pomerium/pull/1565) (@renovate[bot])
- chore\(deps\): update olegtarasov/get-tag action to v2 [\#1552](https://github.com/pomerium/pomerium/pull/1552) (@renovate[bot])
- chore\(deps\): update goreleaser/goreleaser-action action to v2 [\#1551](https://github.com/pomerium/pomerium/pull/1551) (@renovate[bot])
- chore\(deps\): update actions/setup-go action to v2 [\#1550](https://github.com/pomerium/pomerium/pull/1550) (@renovate[bot])
- chore\(deps\): update toolmantim/release-drafter action to v5.12.1 [\#1549](https://github.com/pomerium/pomerium/pull/1549) (@renovate[bot])
- chore\(deps\): update module google.golang.org/grpc to v1.33.1 [\#1548](https://github.com/pomerium/pomerium/pull/1548) (@renovate[bot])
- chore\(deps\): update codecov/codecov-action action to v1.0.14 [\#1547](https://github.com/pomerium/pomerium/pull/1547) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 0ff5f38 [\#1546](https://github.com/pomerium/pomerium/pull/1546) (@renovate[bot])
- chore\(deps\): update golang.org/x/sync commit hash to 67f06af [\#1545](https://github.com/pomerium/pomerium/pull/1545) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to be3efd7 [\#1544](https://github.com/pomerium/pomerium/pull/1544) (@renovate[bot])
- chore\(deps\): update vuepress monorepo to v1.7.1 [\#1531](https://github.com/pomerium/pomerium/pull/1531) (@renovate[bot])
- chore\(deps\): update module spf13/cobra to v1.1.1 [\#1530](https://github.com/pomerium/pomerium/pull/1530) (@renovate[bot])
- chore\(deps\): update module prometheus/client\_golang to v1.8.0 [\#1529](https://github.com/pomerium/pomerium/pull/1529) (@renovate[bot])
- chore\(deps\): update module ory/dockertest/v3 to v3.6.2 [\#1528](https://github.com/pomerium/pomerium/pull/1528) (@renovate[bot])
- chore\(deps\): update module open-policy-agent/opa to v0.24.0 [\#1527](https://github.com/pomerium/pomerium/pull/1527) (@renovate[bot])
- chore\(deps\): update module golang/protobuf to v1.4.3 [\#1525](https://github.com/pomerium/pomerium/pull/1525) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 32ed001 [\#1524](https://github.com/pomerium/pomerium/pull/1524) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to 7b1cca2 [\#1523](https://github.com/pomerium/pomerium/pull/1523) (@renovate[bot])
- chore\(deps\): update golang.org/x/crypto commit hash to 9e8e0b3 [\#1522](https://github.com/pomerium/pomerium/pull/1522) (@renovate[bot])
- chore\(deps\): upgrade envoy to v0.16.0 [\#1519](https://github.com/pomerium/pomerium/pull/1519) (@desimone)
- deployment: run go mod tidy [\#1512](https://github.com/pomerium/pomerium/pull/1512) (@desimone)
- chore\(deps\): update module ory/dockertest/v3 to v3.6.1 [\#1511](https://github.com/pomerium/pomerium/pull/1511) (@renovate[bot])
- chore\(deps\): update module go.opencensus.io to v0.22.5 [\#1510](https://github.com/pomerium/pomerium/pull/1510) (@renovate[bot])
- chore\(deps\): update module cenkalti/backoff/v4 to v4.1.0 [\#1509](https://github.com/pomerium/pomerium/pull/1509) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 4d944d3 [\#1508](https://github.com/pomerium/pomerium/pull/1508) (@renovate[bot])
- chore\(deps\): update golang.org/x/sync commit hash to b3e1573 [\#1507](https://github.com/pomerium/pomerium/pull/1507) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to 4f7140c [\#1506](https://github.com/pomerium/pomerium/pull/1506) (@renovate[bot])
- deployment: pin /x/sys to fix dockertest [\#1491](https://github.com/pomerium/pomerium/pull/1491) (@desimone)
- chore\(deps\): update module openzipkin/zipkin-go to v0.2.5 [\#1488](https://github.com/pomerium/pomerium/pull/1488) (@renovate[bot])
- chore\(deps\): update module envoyproxy/go-control-plane to v0.9.7 [\#1487](https://github.com/pomerium/pomerium/pull/1487) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to bcad7cf [\#1486](https://github.com/pomerium/pomerium/pull/1486) (@renovate[bot])
- chore\(deps\): update golang.org/x/sync commit hash to 3042136 [\#1485](https://github.com/pomerium/pomerium/pull/1485) (@renovate[bot])
- chore\(deps\): update golang.org/x/crypto commit hash to 7f63de1 [\#1483](https://github.com/pomerium/pomerium/pull/1483) (@renovate[bot])
- deps: update envoy arm64 to v1.15.1 [\#1475](https://github.com/pomerium/pomerium/pull/1475) (@travisgroth)
- chore\(deps\): envoy 1.15.1 [\#1473](https://github.com/pomerium/pomerium/pull/1473) (@desimone)
- chore\(deps\): update vuepress monorepo to v1.6.0 [\#1463](https://github.com/pomerium/pomerium/pull/1463) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to c2d885f [\#1462](https://github.com/pomerium/pomerium/pull/1462) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to 5d4f700 [\#1461](https://github.com/pomerium/pomerium/pull/1461) (@renovate[bot])
- deps: go mod tidy [\#1434](https://github.com/pomerium/pomerium/pull/1434) (@travisgroth)
- chore\(deps\): update module rs/zerolog to v1.20.0 [\#1431](https://github.com/pomerium/pomerium/pull/1431) (@renovate[bot])
- chore\(deps\): update module caddyserver/certmagic to v0.12.0 [\#1429](https://github.com/pomerium/pomerium/pull/1429) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to d0d6055 [\#1428](https://github.com/pomerium/pomerium/pull/1428) (@renovate[bot])
- chore\(deps\): update module openzipkin/zipkin-go to v0.2.4 [\#1407](https://github.com/pomerium/pomerium/pull/1407) (@renovate[bot])
- chore\(deps\): update module gorilla/handlers to v1.5.1 [\#1406](https://github.com/pomerium/pomerium/pull/1406) (@renovate[bot])
- chore\(deps\): update module google.golang.org/grpc to v1.32.0 [\#1405](https://github.com/pomerium/pomerium/pull/1405) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 645f7a4 [\#1404](https://github.com/pomerium/pomerium/pull/1404) (@renovate[bot])
- Run go mod tidy [\#1384](https://github.com/pomerium/pomerium/pull/1384) (@cuonglm)
- chore\(deps\): update module go.uber.org/zap to v1.16.0 [\#1381](https://github.com/pomerium/pomerium/pull/1381) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 0bd0a95 [\#1380](https://github.com/pomerium/pomerium/pull/1380) (@renovate[bot])
- chore\(deps\): update golang.org/x/oauth2 commit hash to 5d25da1 [\#1379](https://github.com/pomerium/pomerium/pull/1379) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to 62affa3 [\#1378](https://github.com/pomerium/pomerium/pull/1378) (@renovate[bot])
- deps: ensure renovate runs `go mod tidy` [\#1357](https://github.com/pomerium/pomerium/pull/1357) (@travisgroth)
- deps: go mod tidy [\#1356](https://github.com/pomerium/pomerium/pull/1356) (@travisgroth)
- Update module open-policy-agent/opa to v0.23.2 [\#1351](https://github.com/pomerium/pomerium/pull/1351) (@renovate[bot])
- Update module google/uuid to v1.1.2 [\#1350](https://github.com/pomerium/pomerium/pull/1350) (@renovate[bot])
- Update module google/go-cmp to v0.5.2 [\#1349](https://github.com/pomerium/pomerium/pull/1349) (@renovate[bot])
- Update module google.golang.org/grpc to v1.31.1 [\#1348](https://github.com/pomerium/pomerium/pull/1348) (@renovate[bot])
- Update google.golang.org/genproto commit hash to 2bf3329 [\#1347](https://github.com/pomerium/pomerium/pull/1347) (@renovate[bot])
- chore\(deps\): update vuepress monorepo to v1.5.4 [\#1323](https://github.com/pomerium/pomerium/pull/1323) (@renovate[bot])
- chore\(deps\): update module open-policy-agent/opa to v0.23.1 [\#1322](https://github.com/pomerium/pomerium/pull/1322) (@renovate[bot])
- chore\(deps\): update module gorilla/mux to v1.8.0 [\#1321](https://github.com/pomerium/pomerium/pull/1321) (@renovate[bot])
- chore\(deps\): update module gorilla/handlers to v1.5.0 [\#1320](https://github.com/pomerium/pomerium/pull/1320) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to c890458 [\#1319](https://github.com/pomerium/pomerium/pull/1319) (@renovate[bot])
- chore\(deps\): update golang.org/x/crypto commit hash to 5c72a88 [\#1318](https://github.com/pomerium/pomerium/pull/1318) (@renovate[bot])
- Upgrade zipkin-go to v0.2.3 [\#1288](https://github.com/pomerium/pomerium/pull/1288) (@cuonglm)
- chore\(deps\): update google.golang.org/genproto commit hash to f69a880 [\#1286](https://github.com/pomerium/pomerium/pull/1286) (@renovate[bot])
- chore\(deps\): update golang.org/x/time commit hash to 3af7569 [\#1285](https://github.com/pomerium/pomerium/pull/1285) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to 3edf25e [\#1284](https://github.com/pomerium/pomerium/pull/1284) (@renovate[bot])
- .github/workflows: upgrade to go1.15 [\#1258](https://github.com/pomerium/pomerium/pull/1258) (@cuonglm)
- Fix tests failed with go115 [\#1257](https://github.com/pomerium/pomerium/pull/1257) (@cuonglm)
- chore\(deps\): update dependency @vuepress/plugin-google-analytics to v1.5.3 [\#1236](https://github.com/pomerium/pomerium/pull/1236) (@renovate[bot])
- Update module google.golang.org/api to v0.30.0 [\#1235](https://github.com/pomerium/pomerium/pull/1235) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to a062522 [\#1234](https://github.com/pomerium/pomerium/pull/1234) (@renovate[bot])

## Deployment

- ci: automatically update test environment with master [\#1562](https://github.com/pomerium/pomerium/pull/1562) (@travisgroth)
- deplyoment: add debug build / container / docs [\#1513](https://github.com/pomerium/pomerium/pull/1513) (@travisgroth)
- deployment: Generate deb and rpm packages [\#1458](https://github.com/pomerium/pomerium/pull/1458) (@travisgroth)
- deployment: bump release go to v1.15.x [\#1439](https://github.com/pomerium/pomerium/pull/1439) (@desimone)
- ci: publish cloudrun latest tag [\#1398](https://github.com/pomerium/pomerium/pull/1398) (@travisgroth)
- deployment: fully split release archives and brews [\#1365](https://github.com/pomerium/pomerium/pull/1365) (@travisgroth)
- Include pomerium-cli in the docker image by default.  Fixes \#1343. [\#1345](https://github.com/pomerium/pomerium/pull/1345) (@rspier)
- Use apt-get instead of apt to eliminate warning. [\#1344](https://github.com/pomerium/pomerium/pull/1344) (@rspier)
- deployment: add goimports with path awareness [\#1316](https://github.com/pomerium/pomerium/pull/1316) (@desimone)

## Changed

- ci: fix release workflow syntax [\#1592](https://github.com/pomerium/pomerium/pull/1592) (@travisgroth)
- ci: update changelog generation to script [\#1589](https://github.com/pomerium/pomerium/pull/1589) (@travisgroth)
- \[Backport 0-10-0\] docs: add round logo [\#1575](https://github.com/pomerium/pomerium/pull/1575) (@github-actions[bot])
- tidy [\#1494](https://github.com/pomerium/pomerium/pull/1494) (@desimone)
- dev: add remote container debug configs [\#1459](https://github.com/pomerium/pomerium/pull/1459) (@desimone)
- ci: add stale issue automation [\#1366](https://github.com/pomerium/pomerium/pull/1366) (@travisgroth)
- internal/urlutil: remove un-used constants [\#1326](https://github.com/pomerium/pomerium/pull/1326) (@cuonglm)
- integration: add forward auth test [\#1312](https://github.com/pomerium/pomerium/pull/1312) (@cuonglm)
- pkg/storage/redis: update tests to use local certs + upstream image [\#1306](https://github.com/pomerium/pomerium/pull/1306) (@travisgroth)
- config: omit empty subpolicies in yaml/json [\#1229](https://github.com/pomerium/pomerium/pull/1229) (@travisgroth)
- Cuonglm/increase coverrage 1 [\#1227](https://github.com/pomerium/pomerium/pull/1227) (@cuonglm)

## [v0.10.6](https://github.com/pomerium/pomerium/tree/v0.10.6) (2020-09-30)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.10.5...v0.10.6)

## Changed

- docs: Update changelog for v0.10.6 [\#1477](https://github.com/pomerium/pomerium/pull/1477) (@travisgroth)
- \[Backport 0-10-0\] deps: update envoy arm64 to v1.15.1 [\#1476](https://github.com/pomerium/pomerium/pull/1476) (@github-actions[bot])
- \[Backport 0-10-0\] chore\(deps\): envoy 1.15.1 [\#1474](https://github.com/pomerium/pomerium/pull/1474) (@github-actions[bot])

## [v0.10.5](https://github.com/pomerium/pomerium/tree/v0.10.5) (2020-09-28)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.10.4...v0.10.5)

## Documentation

- docs: Update changelog for v0.10.5 [\#1469](https://github.com/pomerium/pomerium/pull/1469) (@travisgroth)

## Changed

- redis: use pubsub instead of keyspace events [\#1451](https://github.com/pomerium/pomerium/pull/1451) (@calebdoxsey)

## [v0.10.4](https://github.com/pomerium/pomerium/tree/v0.10.4) (2020-09-22)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.10.3...v0.10.4)

## Documentation

- docs: update 0.10.4 changelog [\#1441](https://github.com/pomerium/pomerium/pull/1441) (@travisgroth)
- Add v0.10.4 changelog entry [\#1437](https://github.com/pomerium/pomerium/pull/1437) (@travisgroth)

## Changed

- \[Backport 0-10-0\] httputil: remove retry button [\#1440](https://github.com/pomerium/pomerium/pull/1440) (@github-actions[bot])
- \[Backport 0-10-0\] proxy: always use https for application callback [\#1435](https://github.com/pomerium/pomerium/pull/1435) (@github-actions[bot])
- \[Backport 0-10-0\] redirect-server: add config headers to responses [\#1427](https://github.com/pomerium/pomerium/pull/1427) (@github-actions[bot])
- \[Backport 0-10-0\] controplane: remove p-521 EC [\#1423](https://github.com/pomerium/pomerium/pull/1423) (@github-actions[bot])
- \[Backport 0-10-0\] controlplane: support P-384 / P-512 EC curves [\#1410](https://github.com/pomerium/pomerium/pull/1410) (@github-actions[bot])

## [v0.10.3](https://github.com/pomerium/pomerium/tree/v0.10.3) (2020-09-11)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.10.2...v0.10.3)

## Changed

- Update changelog for v0.10.3 [\#1401](https://github.com/pomerium/pomerium/pull/1401) (@travisgroth)
- \[Backport 0-10-0\] ci: publish cloudrun latest tag [\#1399](https://github.com/pomerium/pomerium/pull/1399) (@github-actions[bot])
- \[Backport 0-10-0\] proxy: remove impersonate headers for kubernetes [\#1396](https://github.com/pomerium/pomerium/pull/1396) (@travisgroth)
- \[Backport 0-10-0\] docs: update azure docs [\#1385](https://github.com/pomerium/pomerium/pull/1385) (@github-actions[bot])
- internal/directory/okta: remove rate limiter \(\#1370\) [\#1371](https://github.com/pomerium/pomerium/pull/1371) (@cuonglm)
- \[Backport 0-10-0\] internal/directory/okta: acceept non-json service account [\#1360](https://github.com/pomerium/pomerium/pull/1360) (@github-actions[bot])
- \[Backport 0-10-0\] internal/controlplane: add telemetry http handler [\#1355](https://github.com/pomerium/pomerium/pull/1355) (@github-actions[bot])
- \[Backport 0-10-0\] docs: add nginx example [\#1339](https://github.com/pomerium/pomerium/pull/1339) (@github-actions[bot])

## [v0.10.2](https://github.com/pomerium/pomerium/tree/v0.10.2) (2020-08-26)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.10.1...v0.10.2)

## Documentation

- docs: update change log for 0.10.2 [\#1330](https://github.com/pomerium/pomerium/pull/1330) (@travisgroth)

## Changed

- Backport go 1.15 changes for 0-10-0 [\#1334](https://github.com/pomerium/pomerium/pull/1334) (@travisgroth)
- \[Backport 0-10-0\] internal/directory/okta: improve API requests [\#1332](https://github.com/pomerium/pomerium/pull/1332) (@travisgroth)
- autocert: fix locking issue \(\#1310\) [\#1311](https://github.com/pomerium/pomerium/pull/1311) (@calebdoxsey)

## [v0.10.1](https://github.com/pomerium/pomerium/tree/v0.10.1) (2020-08-20)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.10.0...v0.10.1)

## Documentation

- \[Backport 0-10-0\] Docs/enterprise button [\#1246](https://github.com/pomerium/pomerium/pull/1246) (@github-actions[bot])
- \[Backport 0-10-0\] docs: add / redirect [\#1242](https://github.com/pomerium/pomerium/pull/1242) (@github-actions[bot])

## Changed

- docs: v0.10.1 changelog [\#1308](https://github.com/pomerium/pomerium/pull/1308) (@travisgroth)
- \[Backport 0-10-0\] pkg/storage/redis: update tests to use local certs + upstream image [\#1307](https://github.com/pomerium/pomerium/pull/1307) (@github-actions[bot])
- azure: support deriving credentials from client id, client secret and… [\#1301](https://github.com/pomerium/pomerium/pull/1301) (@calebdoxsey)
- \[Backport 0-10-0\] autocert: fix  bootstrapped cache store path [\#1291](https://github.com/pomerium/pomerium/pull/1291) (@github-actions[bot])
- \[Backport 0-10-0\] docs: use .com sitemap hostname [\#1275](https://github.com/pomerium/pomerium/pull/1275) (@github-actions[bot])
- \[Backport 0-10-0\] docs: fix in-action video [\#1269](https://github.com/pomerium/pomerium/pull/1269) (@github-actions[bot])
- \[Backport 0-10-0\] docs: image, sitemap and redirect fixes [\#1265](https://github.com/pomerium/pomerium/pull/1265) (@github-actions[bot])
- \[Backport 0-10-0\] docs: prepare for enterprise / oss split [\#1239](https://github.com/pomerium/pomerium/pull/1239) (@github-actions[bot])
- \[Backport 0-10-0\] authorize: add databroker url check [\#1231](https://github.com/pomerium/pomerium/pull/1231) (@github-actions[bot])
- \[Backport 0-10-0\] config: omit empty subpolicies in yaml/json [\#1230](https://github.com/pomerium/pomerium/pull/1230) (@github-actions[bot])


## v0.10.0

### Changes

- Add storage backend interface @cuonglm GH-1072
- all: update outdated comments about OptionsUpdater interface @cuonglm GH-1207
- Allow specify go executable in Makefile @cuonglm GH-1008
- audit: add protobuf definitions @calebdoxsey GH-1047
- authenticate: hide impersonation form from non-admin users @cuonglm GH-979
- authenticate: move impersonate from proxy to authenticate @calebdoxsey GH-965
- authenticate: remove useless/duplicated code block @cuonglm GH-962
- authenticate: revoke current session oauth token before sign out @cuonglm GH-964
- authorize,proxy: allow traefik forward auth without uri query @cuonglm GH-1103
- authorize: add evaluator store @calebdoxsey GH-1105
- authorize: add test for denied response @cuonglm GH-1197
- authorize: avoid serializing databroker data map to improve performance @calebdoxsey GH-995
- authorize: clear session state if session was deleted in databroker @cuonglm GH-1053
- authorize: derive check response message from reply message @cuonglm GH-1193
- authorize: include "kid" in JWT header @cuonglm GH-1049
- authorize: store policy evaluator on success only @cuonglm GH-1206
- authorize/evaluator: add more test cases @cuonglm GH-1198
- authorize/evaluator: fix wrong custom policies decision @cuonglm GH-1199
- authorize/evaluator/opa: use route policy object instead of array index @cuonglm GH-1001
- cache: add client telemetry @travisgroth GH-975
- cache: add test for runMemberList @cuonglm GH-1007
- cache: attempt to join memberlist cluster for sanity check @travisgroth GH-1004
- cache: fix missing parameter @travisgroth GH-1005
- cache: only run memberlist for in-memory databroker @travisgroth GH-1224
- ci: Add cloudrun build @travisgroth GH-1097
- ci: support rc releases @travisgroth GH-1011
- cmd/pomerium-cli: do not require terminal with cached creds @travisgroth GH-1196
- config: add check to assert service account is required for policies with allowed_groups @desimone GH-997
- config: add support for policies stored in the databroker @calebdoxsey GH-1099
- config: additional kubernetes token source support @travisgroth GH-1200
- config: allow setting directory sync interval and timeout @cuonglm GH-1098
- config: default to google idp credentials for serverless @travisgroth GH-1170
- config: fix loading storage client cert from wrong location @travisgroth GH-1212
- config: Set loopback address by ipv4 IP @travisgroth GH-1116
- cryptutil: move to pkg dir, add token generator @calebdoxsey GH-1029
- deployment: fix brew creation for pomerium-cli @travisgroth GH-1192
- directory.Group entry for groups @calebdoxsey GH-1118
- docs/docs: update upgrading to mention redis storage backend @cuonglm GH-1172
- envoy: disable idle timeouts to controlplane @travisgroth GH-1000
- grpc: rename internal/grpc to pkg/grpc @calebdoxsey GH-1010
- grpc: use relative paths in codegen @desimone GH-1106
- grpcutil: add functions for JWTs in gRPC metadata @calebdoxsey GH-1165
- Increasing authorize coverage @cuonglm GH-1221
- integration: add dummy value for idp_service_account @cuonglm GH-1009
- internal/controlplane: set envoy prefix rewrite if present @cuonglm GH-1034
- internal/controlplane: using envoy strip host port matching @cuonglm GH-1126
- internal/databroker: handle new db error @cuonglm GH-1129
- internal/databroker: store server version @cuonglm GH-1121
- internal/directory: improve google user groups list @cuonglm GH-1092
- internal/directory: use both id and name for group @cuonglm GH-1086
- internal/directory/google: return both group e-mail and id @travisgroth GH-1083
- internal/frontend/assets/html: make timestamp human readable @cuonglm GH-1107
- internal/sessions: handle claims "ver" field generally @cuonglm GH-990
- internal/urlutil: add tests for GetDomainsForURL @cuonglm GH-1183
- memberlist: use bufio reader instead of scanner @calebdoxsey GH-1002
- config: options refactor @calebdoxsey GH-1088
- pkg: add grpcutil package @calebdoxsey GH-1032
- pkg/storage: add package docs @cuonglm GH-1078
- pkg/storage: change backend interface to return error @cuonglm GH-1131
- pkg/storage: introduce storage.Backend Watch method @cuonglm GH-1135
- pkg/storage: make Watch returns receive only channel @cuonglm GH-1211
- pkg/storage/redis: do not use timeout to signal redis conn to stop @cuonglm GH-1155
- pkg/storage/redis: fix multiple data race @cuonglm GH-1210
- pkg/storage/redis: metrics updates @travisgroth GH-1195
- pkg/storage/redis: move last version to redis @cuonglm GH-1134
- proxy: add support for spdy upgrades @travisgroth GH-1203
- proxy: avoid second policy validation @travisgroth GH-1204
- proxy: refactor handler setup code @travisgroth GH-1205
- set session state expiry @calebdoxsey GH-1215
- Sleep longer before running integration tests @cuonglm GH-968
- telemetry: add tracing spans to cache and databroker @travisgroth GH-987

### New

- authenticate: allow hot reloaded admin users config @cuonglm [GH-984]
- authenticate: support hot reloaded config @cuonglm GH-984
- authorize: custom rego policies @calebdoxsey GH-1123
- authorize: include "kid" in JWT headers @cuonglm [GH-1046]
- azure: use OID for user id in session @calebdoxsey GH-985
- config: add pass_identity_headers @cuonglm [GH-903]
- config: add remove_request_headers @cuonglm [GH-822]
- config: both base64 and file reference can be used for "certificates" @dmitrif [GH-1055]
- config: change config key parsing to attempt Base64 decoding first. @dmitrif GH-1055
- config: change default log level to INFO @cuonglm [GH-902]
- custom rego in databroker @calebdoxsey GH-1124
- databroker server backend config @cuonglm GH-1127
- databroker: add encryption for records @calebdoxsey GH-1168
- deploy: Add homebrew tap publishing @travisgroth GH-1179
- deployment: cut separate archive for cli @desimone GH-1177
- directory: add service account struct and parsing method @calebdoxsey GH-971
- envoy: enable strip host port matching @cuonglm [GH-1126]
- github: implement github directory provider @calebdoxsey GH-963
- google: store directory information by user id @calebdoxsey GH-988
- identity: support custom code flow request params @desimone GH-998
- implement google cloud serverless authentication @calebdoxsey GH-1080
- internal/directory/okta: store directory information by user id @cuonglm GH-991
- internal/directory/onelogin: store directory information by user id @cuonglm GH-992
- kubernetes apiserver integration @calebdoxsey GH-1063
- pkg/storage/redis: add authentication support @cuonglm GH-1159
- pkg/storage/redis: add redis TLS support @cuonglm GH-1163
- pomerium-cli k8s exec-credential @calebdoxsey GH-1073
- redis storage backend @cuonglm GH-1082
- telmetry: add databroker storage metrics and tracing @travisgroth GH-1161
- use custom binary for arm64 linux release @calebdoxsey GH-1065

### Fixed

- authenticate: fix wrong condition checking in VerifySession @cuonglm GH-1146
- authenticate: fix wrong SignIn telemetry name @cuonglm GH-1038
- authorize: Force redirect scheme to https @travisgroth GH-1075
- authorize: strip port from host header if necessary @cuonglm GH-1175
- authorize/evaluator/opa: set client tls cert usage explicitly @travisgroth GH-1026
- authorize/evaluator/opa/policy: fix allow rules with impersonate @cuonglm GH-1094
- cache: fix data race in NotifyJoin @cuonglm GH-1028
- ci: fix arm docker image releases @travisgroth GH-1178
- ci: Prevent dirty git state @travisgroth GH-1117
- ci: release fixes @travisgroth GH-1181
- config: fix deep copy of config @calebdoxsey GH-1089
- controlplane: add robots route @desimone GH-966
- deploy: ensure pomerium-cli is built correctly @travisgroth GH-1180
- deployment: fix pomerium-cli release @desimone GH-1104
- envoy: Set ExtAuthz Cluster name to URL Host @travisgroth GH-1132
- fix databroker restart versioning, handle missing sessions @calebdoxsey GH-1145
- fix lint errors @travisgroth GH-1171
- fix redirect loop, remove user/session services, remove duplicate deleted_at fields @calebdoxsey GH-1162
- handle example.com and example.com:443 @calebdoxsey GH-1153
- internal/controlplane: enable envoy use remote address @cuonglm GH-1023
- internal/databroker: fix wrong server version init @cuonglm GH-1125
- pkg/grpc: fix wrong audit protoc gen file @cuonglm GH-1048
- pkg/storage/redis: handling connection to redis backend failure @cuonglm GH-1174
- pomerium-cli: fix kubernetes token caching @calebdoxsey GH-1169
- pomerium-cli: kubernetes fixes @calebdoxsey GH-1176
- proxy: do not set X-Pomerium-Jwt-Assertion/X-Pomerium-Claim-* headers by default @cuonglm [GH-903]
- proxy: fix invalid session after logout in forward auth mode @cuonglm GH-1062
- proxy: fix redirect url with traefik forward auth @cuonglm GH-1037
- proxy: fix wrong forward auth request @cuonglm GH-1030

### Documentation

- docs: Update synology.md @roulesse GH-1219
- docs: add installation section @travisgroth GH-1223
- docs: add kubectl config commands @travisgroth GH-1152
- docs: add kubernetes docs @calebdoxsey GH-1087
- docs: add recipe for TiddlyWiki on Node.js @favadi GH-1143
- docs: add required in cookie_secret @mig4ng GH-1142
- docs: add warnings cones around requiring IdP Service Accounts @travisgroth GH-999
- docs: cloud Run / GCP Serverless @travisgroth GH-1101
- docs: document preserve_host_header with policy routes to static ip @cuonglm GH-1024
- docs: fix incorrect example middleware @travisgroth GH-1128
- docs: fix links, clarify upgrade guide for v0.10 @desimone GH-1220
- docs: fix minor errors @travisgroth GH-1214
- docs: Kubernetes topic @travisgroth GH-1222
- docs: Move examples repo into main repo @travisgroth GH-1102
- docs: Redis and stateful storage docs @travisgroth GH-1173
- docs: refactor sections, consolidate examples @desimone GH-1164
- docs: rename docs/reference to docs/topics @desimone GH-1182
- docs: service account instructions for azure @calebdoxsey GH-969
- docs: service account instructions for gitlab @calebdoxsey GH-970
- docs: update architecture diagrams + descriptions @travisgroth GH-1218
- docs: update GitHub documentation for service account @calebdoxsey GH-967
- docs: Update Istio VirtualService example @jeffhubLR GH-1006
- docs: update okta service account docs to match new format @calebdoxsey GH-972
- Docs: Update README stating specific requirements for SIGNING_KEY @bradjones1 GH-1217
- docs: update reference docs @desimone GH-1208
- docs: update service account instructions for OneLogin @calebdoxsey GH-973
- docs: update upgrading document for breaking changes @calebdoxsey GH-974
- docs/.vuepress: fix missing local-oidc recipes section @cuonglm GH-1147
- docs/configuration: add doc for trailing slash limitation in "To" field @cuonglm GH-1040
- docs/docs: add changelog for #1055 @cuonglm GH-1084
- docs/docs/identity-providers: document gitlab default scopes changed @cuonglm GH-980
- docs/recipes: add local oidc example @cuonglm GH-1045

### Dependency

- chore(deps): bump envoy to 1.15.0 @desimone GH-1119
- chore(deps): google.golang.org/genproto commit hash to da3ae01 @renovate GH-1138
- chore(deps): module google/go-cmp to v0.5.1 @renovate GH-1139
- chore(deps): update envoy to 1.14.4 @desimone GH-1076
- chore(deps): update github.com/skratchdot/open-golang commit hash to eef8423 @renovate GH-1108
- chore(deps): update golang.org/x/crypto commit hash to 123391f @renovate GH-1184
- chore(deps): update golang.org/x/crypto commit hash to 948cd5f @renovate GH-1056
- chore(deps): update golang.org/x/net commit hash to 4c52546 @renovate GH-1017
- chore(deps): update golang.org/x/net commit hash to ab34263 @renovate GH-1057
- chore(deps): update golang.org/x/sync commit hash to 6e8e738 @renovate GH-1018
- chore(deps): update google.golang.org/genproto commit hash to 11fb19a @renovate GH-1109
- chore(deps): update google.golang.org/genproto commit hash to 8145dea @renovate GH-1185
- chore(deps): update google.golang.org/genproto commit hash to 8698661 @renovate GH-1058
- chore(deps): update google.golang.org/genproto commit hash to 8e8330b @renovate GH-1039
- chore(deps): update google.golang.org/genproto commit hash to ee7919e @renovate GH-1019
- chore(deps): update google.golang.org/genproto commit hash to fbb79ea @renovate GH-945
- chore(deps): update module cenkalti/backoff/v4 to v4.0.2 @renovate GH-946
- chore(deps): update module contrib.go.opencensus.io/exporter/jaeger to v0.2.1 @renovate GH-1186
- chore(deps): update module contrib.go.opencensus.io/exporter/zipkin to v0.1.2 @renovate GH-1187
- chore(deps): update module envoyproxy/go-control-plane to v0.9.6 @renovate GH-1059
- chore(deps): update module go.opencensus.io to v0.22.4 @renovate GH-948
- chore(deps): update module golang/mock to v1.4.4 @renovate GH-1188
- chore(deps): update module google.golang.org/api to v0.28.0 @renovate GH-949
- chore(deps): update module google.golang.org/api to v0.29.0 @renovate GH-1060
- chore(deps): update module google.golang.org/grpc to v1.30.0 @renovate GH-1020
- chore(deps): update module google.golang.org/grpc to v1.31.0 @renovate GH-1189
- chore(deps): update module google.golang.org/protobuf to v1.25.0 @renovate GH-1021
- chore(deps): update module google/go-cmp to v0.5.0 @renovate GH-950
- chore(deps): update module hashicorp/memberlist to v0.2.2 @renovate GH-951
- chore(deps): update module open-policy-agent/opa to v0.21.0 @renovate GH-952
- chore(deps): update module open-policy-agent/opa to v0.21.1 @renovate GH-1061
- chore(deps): update module open-policy-agent/opa to v0.22.0 @renovate GH-1110
- chore(deps): update module prometheus/client_golang to v1.7.0 @renovate GH-953
- chore(deps): update module prometheus/client_golang to v1.7.1 @renovate GH-1022
- chore(deps): update module spf13/cobra to v1 @renovate GH-1111
- chore(deps): update module spf13/viper to v1.7.1 @renovate GH-1190
- chore(deps):s bump opa v0.21.0 @desimone GH-993

## v0.9.1

### Security

- envoy: fixes CVE-2020-11080 by rejecting HTTP/2 SETTINGS frames with too many parameters

## v0.9.0

### New

- proxy: envoy is now used to handle proxying
- authenticate: add jwks and .well-known endpoint @desimone [GH-745]
- authorize: add client mTLS support @calebdoxsey [GH-751]

### Fixed

- cache: fix closing too early @calebdoxsey [GH-791]
- authenticate: fix insecure gRPC connection string default port @calebdoxsey [GH-795]
- authenticate: fix user-info call for AWS cognito @calebdoxsey [GH-792]
- authenticate: clear session if ctx fails @desimone [GH-806]
- telemetry: fix autocache labels @travisgroth [GH-805]
- telemetry: fix missing/incorrect grpc labels @travisgroth [GH-804]
- authorize: fix authorization panic caused by logging a nil reference @desimone [GH-704]

### Changes

- authenticate: remove authorize url validate check @calebdoxsey [GH-790]
- authorize: reduce log noise for empty jwt @calebdoxsey [GH-793]
- authorize: refactor and add additional unit tests @calebdoxsey [GH-757]
- envoy: add GRPC stats handler to control plane service @travisgroth [GH-744]
- envoy: enable zipkin tracing @travisgroth [GH-737]
- envoy: improvements to logging @calebdoxsey [GH-742]
- envoy: remove 'accept-encoding' header from proxied metric requests @travisgroth [GH-750]
- envoy: support ports in hosts for routing @calebdoxsey [GH-748]
- forward-auth: support x-forwarded-uri @calebdoxsey [GH-780]
- proxy/forward-auth: block expired request prior to 302 @desimone [GH-773]
- sessions/state: add nickname claim @BenoitKnecht [GH-755]
- state: infer user (`user`) from subject (`sub`) @desimone [GH-772]
- telemetry: refactor GRPC Server Handler @travisgroth [GH-756]
- telemetry: service label updates @travisgroth [GH-802]
- xds: add catch-all for pomerium routes @calebdoxsey [GH-789]
- xds: disable cluster validation to handle out-of-order updates @calebdoxsey [GH-783]

### Documentation

- docs: add mTLS recipe @calebdoxsey [GH-807]
- docs: add argo recipe @calebdoxsey [GH-803]
- docs: update dockerfiles for v0.9.0 @calebdoxsey [GH-801]
- docs: typo on configuration doc @kintoandar [GH-800]
- docs: docs regarding claim headers @strideynet [GH-782]
- docs: update traefik example and add note about forwarded headers @calebdoxsey [GH-784]
- docs: add note about unsupported platforms @calebdoxsey [GH-799]
- docs: expose config parameters in sidebar @travisgroth [GH-797]
- docs: update examples @travisgroth [GH-796]

## v0.8.3

### Changes

- state: infer user (`user`) from subject (`sub`) @desimone GH-772
- proxy/forward-auth: block expired request prior to 302 @desimone GH-773

## v0.8.2

### Security

This release includes a fix for a bug that, under certain circumstances, could allow a user with a valid but expired session to resend a request to an upstream application. The repeated request would not return a response, but could reach the upstream application. Thank you to @selaux for reporting this issue! [GH-762]

## v0.8.1

### Fixed

- authorize: fix authorization panic caused by logging a nil reference @desimone [GH-704]

## v0.8.0

To see a complete list of changes [see the diff](https://github.com/pomerium/pomerium/compare/v0.7.0...v0.8.0).

### New

- cryptutil: add automatic certificate management @desimone [GH-644]
- implement path-based route matching @calebdoxsey [GH-615]
- internal/identity: implement github provider support @Lumexralph [GH-582]
- proxy: add configurable JWT claim headers @travisgroth (#596)
- proxy: remove extra session unmarshalling @desimone (#592)

### Changes

- ci: Switch integration tests from minikube to kind @travisgroth [GH-656]
- integration-tests: add CORS test @calebdoxsey [GH-662]
- integration-tests: add websocket enabled/disabled test @calebdoxsey [GH-661]
- integration-tests: set_request_headers and preserve_host_header options @calebdoxsey [GH-668]
- pre-commit: add pre-commit configuration @calebdoxsey [GH-666]
- proxy: improve JWT header behavior @travisgroth [GH-642]

## Fixed

- authorize: fix authorization check for allowed_domains to only match current route @calebdoxsey [GH-624]
- authorize: fix unexpected panic on reload @travisgroth [GH-652]
- site: fix site on mobile @desimone [GH-597]

### Documentation

- deploy: autocert documentation and defaults @travisgroth [GH-658]

## v0.7.5

### Fixed

- authorize: fix authorization check for allowed_domains to only match current route @calebdoxsey [GH-624]

## v0.7.4

### Fixed

- pomerium-cli: fix service account cli @desimone [GH-613]

## v0.7.3

### Fixed

- Upgrade gRPC to 1.27.1 @travisgroth [GH-609]

## v0.7.2

### Changes

- proxy: remove extra session unmarshalling @desimone [GH-592]
- proxy: add configurable JWT claim headers @travisgroth [GH-596]
- grpcutil: remove unused pkg @desimone [GH-593]

### Fixed

- site: fix site on mobile @desimone [GH-597]

### Documentation

- site: fix site on mobile @desimone [GH-597]

### Dependency

- chore(deps): update vuepress monorepo to v1.4.0 @renovate [GH-559]

## v0.7.1

There were no changes in the v0.7.1 release, but we updated the build process slightly.

## v0.7.0

### New

- *: remove import path comments @desimone [GH-545]
- authenticate: make callback path configurable @desimone [GH-493]
- authenticate: return 401 for some specific error codes @cuonglm [GH-561]
- authorization: log audience claim failure @desimone [GH-553]
- authorize: use jwt instead of state struct @desimone [GH-514]
- authorize: use opa for policy engine @desimone [GH-474]
- cmd: add cli to generate service accounts @desimone [GH-552]
- config: Expose and set default GRPC Server Keepalive Parameters @travisgroth [GH-509]
- config: Make IDP_PROVIDER env var mandatory @mihaitodor [GH-536]
- config: Remove superfluous Options.Checksum type conversions @travisgroth [GH-522]
- gitlab/identity: change group unique identifier to ID @Lumexralph [GH-571]
- identity: support oidc UserInfo Response @desimone [GH-529]
- internal/cryptutil: standardize leeway to 5 mins @desimone [GH-476]
- metrics: Add storage metrics @travisgroth [GH-554]

### Fixed

- cache: add option validations @desimone [GH-468]
- config: Add proper yaml tag to Options.Policies @travisgroth [GH-475]
- ensure correct service name on GRPC related metrics @travisgroth [GH-510]
- fix group impersonation @desimone [GH-569]
- fix sign-out bug , fixes #530 @desimone [GH-544]
- proxy: move set request headers before handle allow public access @ohdarling [GH-479]
- use service port for session audiences @travisgroth [GH-562]

### Documentation

- fix `the` typo @ilgooz [GH-566]
- fix kubernetes dashboard recipe docs @desimone [GH-504]
- make from source quickstart @desimone [GH-519]
- update background @desimone [GH-505]
- update helm for v3 @desimone [GH-469]
- various fixes @desimone [GH-478]
- fix cookie_domain @nitper [GH-472]

### Dependency

- chore(deps): update github.com/pomerium/autocache commit hash to 6c66ed5 @renovate [GH-480]
- chore(deps): update github.com/pomerium/autocache commit hash to 227c993 @renovate [GH-537]
- chore(deps): update golang.org/x/crypto commit hash to 0ec3e99 @renovate [GH-574]
- chore(deps): update golang.org/x/crypto commit hash to 1b76d66 @renovate [GH-538]
- chore(deps): update golang.org/x/crypto commit hash to 78000ba @renovate [GH-481]
- chore(deps): update golang.org/x/crypto commit hash to 891825f @renovate [GH-556]
- chore(deps): update module fatih/color to v1.9.0 @renovate [GH-575]
- chore(deps): update module fsnotify/fsnotify to v1.4.9 @renovate [GH-539]
- chore(deps): update module go.etcd.io/bbolt to v1.3.4 @renovate [GH-557]
- chore(deps): update module go.opencensus.io to v0.22.3 @renovate [GH-483]
- chore(deps): update module golang/mock to v1.4.0 @renovate [GH-470]
- chore(deps): update module golang/mock to v1.4.3 @renovate [GH-540]
- chore(deps): update module golang/protobuf to v1.3.4 @renovate [GH-485]
- chore(deps): update module golang/protobuf to v1.3.5 @renovate [GH-541]
- chore(deps): update module google.golang.org/api to v0.20.0 @renovate [GH-495]
- chore(deps): update module google.golang.org/grpc to v1.27.1 @renovate [GH-496]
- chore(deps): update module gorilla/mux to v1.7.4 @renovate [GH-506]
- chore(deps): update module open-policy-agent/opa to v0.17.1 @renovate [GH-497]
- chore(deps): update module open-policy-agent/opa to v0.17.3 @renovate [GH-513]
- chore(deps): update module open-policy-agent/opa to v0.18.0 @renovate [GH-558]
- chore(deps): update module prometheus/client_golang to v1.4.1 @renovate [GH-498]
- chore(deps): update module prometheus/client_golang to v1.5.0 @renovate [GH-531]
- chore(deps): update module prometheus/client_golang to v1.5.1 @renovate [GH-543]
- chore(deps): update module rakyll/statik to v0.1.7 @renovate [GH-517]
- chore(deps): update module rs/zerolog to v1.18.0 @renovate [GH-507]
- chore(deps): update module yaml to v2.2.8 @renovate [GH-471]
- ci: Consolidate matrix build parameters @travisgroth [GH-521]
- dependency: use go mod redis @desimone [GH-528]
- deployment: throw away golanglint-ci defaults @desimone [GH-439]
- deployment: throw away golanglint-ci defaults @desimone [GH-439]
- deps: enable automerge and set labels on renovate PRs @travisgroth [GH-527]
- Roll back grpc to v1.25.1 @travisgroth [GH-484]

## v0.6.0

### New

- authenticate: support backend refresh @desimone [GH-438]
- cache: add cache service @desimone [GH-457]

### Changed

- authorize: consolidate gRPC packages @desimone [GH-443]
- config: added yaml tags to all options struct fields @travisgroth [GH-394],[gh-397]
- config: improved config validation for `shared_secret` @travisgroth [GH-427]
- config: Remove CookieRefresh [GH-428] @u5surf [GH-436]
- config: validate that `shared_key` does not contain whitespace @travisgroth [GH-427]
- httputil : wrap handlers for additional context @desimone [GH-413]
- forward-auth: validate using forwarded uri header @branchmispredictor [GH-600]

### Fixed

- proxy: fix unauthorized redirect loop for forward auth @desimone [GH-448]
- proxy: fixed regression preventing policy reload [GH-396](https://github.com/pomerium/pomerium/pull/396)

### Documentation

- add cookie settings @danderson [GH-429]
- fix typo in forward auth nginx example @travisgroth [GH-445]
- improved sentence flow and other stuff @Rio [GH-422]
- rename fwdauth to be forwardauth @desimone [GH-447]

### Dependency

- chore(deps): update golang.org/x/crypto commit hash to 61a8779 @renovate [GH-452]
- chore(deps): update golang.org/x/crypto commit hash to 530e935 @renovate [GH-458]
- chore(deps): update golang.org/x/crypto commit hash to 53104e6 @renovate [GH-431]
- chore(deps): update golang.org/x/crypto commit hash to e9b2fee @renovate [GH-414]
- chore(deps): update golang.org/x/oauth2 commit hash to 858c2ad @renovate [GH-415]
- chore(deps): update golang.org/x/oauth2 commit hash to bf48bf1 @renovate [GH-453]
- chore(deps): update module google.golang.org/grpc to v1.26.0 @renovate [GH-433]
- chore(deps): update module google/go-cmp to v0.4.0 @renovate [GH-454]
- chore(deps): update module spf13/viper to v1.6.1 @renovate [GH-423]
- chore(deps): update module spf13/viper to v1.6.2 @renovate [GH-459]
- chore(deps): update module square/go-jose to v2.4.1 @renovate [GH-435]

## v0.5.0

### New

- Session state is now route-scoped. Each managed route uses a transparent, signed JSON Web Token (JWT) to assert identity.
- Managed routes no longer need to be under the same subdomain! Access can be delegated to any route, on any domain.
- Programmatic access now also uses JWT tokens. Access tokens are now generated via a standard oauth2 token flow, and credentials can be refreshed for as long as is permitted by the underlying identity provider.
- User dashboard now pulls in additional user context fields (where supported) like the profile picture, first and last name, and so on.

### Security

- Some identity providers (Okta, Onelogin, and Azure) previously used mutable signifiers to set and assert group membership. Group membership for all providers now use globally unique and immutable identifiers when available.

### Changed

- Azure AD identity provider now uses globally unique and immutable `ID` for [group membership](https://docs.microsoft.com/en-us/graph/api/group-get?view=graph-rest-1.0&tabs=http).
- Okta no longer uses tokens to retrieve group membership. Group membership is now fetched using Okta's HTTP API. [Group membership](https://developer.okta.com/docs/reference/api/groups/) is now determined by the globally unique and immutable `ID` field.
- Okta now requires an additional set of credentials to be used to query for group membership set as a [service account](https://www.pomerium.io/docs/reference/reference.html#identity-provider-service-account).
- URLs are no longer validated to be on the same domain-tree as the authenticate service. Managed routes can live on any domain.
- OneLogin no longer uses tokens to retrieve group membership. Group membership is now fetched using OneLogin's HTTP API. [Group membership](https://developers.onelogin.com/openid-connect/api/user-info/) is now determined by the globally unique and immutable `ID` field.

### Removed

- Force refresh has been removed from the dashboard.
- Previous programmatic authentication endpoints (`/api/v1/token`) has been removed and is no longer supported.

### Fixed

- Fixed an issue where cookie sessions would not clear on error.[GH-376]

## v0.4.2

### Security

- Fixes vulnerabilities fixed in [1.13.2](https://groups.google.com/forum/#!topic/golang-announce/lVEm7llp0w0) including CVE-2019-17596.

## v0.4.1

### Fixed

- Fixed an issue where requests handled by forward-auth would not be redirected back to the underlying route after successful authentication and authorization. [GH-363]
- Fixed an issue where requests handled by forward-auth would add an extraneous query-param following sign-in causing issues in some configurations. [GH-366]

## v0.4.0

### New

- Allow setting request headers on a per route basis in policy. [GH-308]
- Support "forward-auth" integration with third-party ingresses and proxies. [nginx](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/), [nginx-ingress](https://kubernetes.github.io/ingress-nginx/examples/auth/oauth-external-auth/), and [Traefik](https://docs.traefik.io/middlewares/forwardauth/) are currently supported. [GH-324]
- Add insecure transport / TLS termination support. [GH-328]
- Add setting to override a route's TLS Server Name. [GH-297]
- Pomerium's session can now be passed as a [bearer-auth header](https://tools.ietf.org/html/rfc6750) or [query string](https://en.wikipedia.org/wiki/Query_string) in addition to as a session cookie.
- Add host to the main request logger middleware. [GH-308]
- Add AWS cognito identity provider settings. [GH-314]

### Security

- The user's original intended location before completing the authentication process is now encrypted and kept confidential from the identity provider. [GH-316]
- Under certain circumstances, where debug logging was enabled, pomerium's shared secret could be leaked to http access logs as a query param. [GH-338]

### Fixed

- Fixed an issue where CSRF would fail if multiple tabs were open. [GH-306]
- Fixed an issue where pomerium would clean double slashes from paths. [GH-262]
- Fixed a bug where the impersonate form would persist an empty string for groups value if none set. [GH-303]
- Fixed HTTP redirect server which was not redirecting the correct hostname.

### Changed

- The healthcheck endpoints (`/ping`) now returns the http status `405` StatusMethodNotAllowed for non-`GET` requests.
- Authenticate service no longer uses gRPC.
- The global request logger now captures the full array of proxies from `X-Forwarded-For`, in addition to just the client IP.
- Options code refactored to eliminate global Viper state. [GH-332]
- Pomerium will no longer default to looking for certificates in the root directory. [GH-328]
- Pomerium will validate that either `insecure_server`, or a valid certificate bundle is set. [GH-328]

### Removed

- Removed `AUTHENTICATE_INTERNAL_URL`/`authenticate_internal_url` which is no longer used.

## v0.3.1

### Security

- Fixes vulnerabilities fixed in [Go 1.13.1](https://groups.google.com/forum/m/#!msg/golang-announce/cszieYyuL9Q/g4Z7pKaqAgAJ) including CVE-2019-16276.

## v0.3.0

### New

- GRPC Improvements. [GH-261] / [GH-69]

  - Enable WaitForReady to allow background retries through transient failures
  - Expose a configurable timeout for backend requests to Authorize and Authenticate
  - Enable DNS round_robin load balancing to Authorize and Authenticate services by default

- Add ability to set client certificates for downstream connections. [GH-259]

### Fixed

- Fixed non-`amd64` based docker images.[GH-284]
- Fixed an issue where stripped cookie headers would result in a cookie full of semi-colons (`Cookie: ;;;`). [GH-285]
- HTTP status codes now better adhere to [RFC7235](https://tools.ietf.org/html/rfc7235). In particular, authentication failures reply with [401 Unauthorized](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401) while authorization failures reply with [403 Forbidden](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/403). [GH-272]

### Changed

- Pomerium will now strip `_csrf` cookies in addition to session cookies. [GH-285]
- Disabled gRPC service config. [GH-280]
- A policy's custom certificate authority can set as a file or a base64 encoded blob(`tls_custom_ca`/`tls_custom_ca_file`). [GH-259]

- Remove references to [service named ports](https://golang.org/src/net/lookup.go) and instead use their numeric equivalent. [GH-266]

## v0.2.1

### Security

- Fixes vulnerabilities fixed in [Go 1.12.8](https://groups.google.com/forum/#!topic/golang-nuts/fCQWxqxP8aA) including CVE-2019-9512, CVE-2019-9514 and CVE-2019-14809.

## v0.2.0

### New

#### Telemetry [GH-35]

- **Tracing** [GH-230] aka distributed tracing, provides insight into the full lifecycles, aka traces, of requests to the system, allowing you to pinpoint failures and performance issues.

  - Add [Jaeger](https://opencensus.io/exporters/supported-exporters/go/jaeger/) support. [GH-230]

- **Metrics** provide quantitative information about processes running inside the system, including counters, gauges, and histograms.

  - Add informational metrics. [GH-227]
  - GRPC Metrics Implementation. [GH-218]

    - Additional GRPC server metrics and request sizes
    - Improved GRPC metrics implementation internals
    - The GRPC method label is now 'grpc_method' and GRPC status is now `grpc_client_status` and `grpc_server_status`

  - HTTP Metrics Implementation. [GH-220]

    - Support HTTP request sizes on client and server side of proxy
    - Improved HTTP metrics implementation internals
    - The HTTP method label is now `http_method`, and HTTP status label is now `http_status`

### Changed

- GRPC version upgraded to v1.22 [GH-219]
- Add support for large cookie sessions by chunking. [GH-211]
- Prefer [curve](https://wiki.mozilla.org/Security/Server_Side_TLS) X25519 to P256 for TLS connections. [GH-233]
- Pomerium and its services will gracefully shutdown on [interrupt signal](http://man7.org/linux/man-pages/man7/signal.7.html). [GH-230]
- [Google](https://developers.google.com/identity/protocols/OpenIDConnect) now prompts the user to select a user account (by adding `select_account` to the sign in url). This allows a user who has multiple accounts at the authorization server to select amongst the multiple accounts that they may have current sessions for.

### FIXED

- Fixed potential race condition when signing requests. [GH-240]
- Fixed panic when reloading configuration in single service mode [GH-247]

## v0.1.0

### NEW

- Add programmatic authentication support. [GH-177]
- Add Prometheus format metrics endpoint. [GH-35]
- Add policy setting to enable self-signed certificate support. [GH-179]
- Add policy setting to skip tls certificate verification. [GH-179]

### CHANGED

- Policy `to` and `from` settings must be set to valid HTTP URLs including [schemes](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier) and hostnames (e.g. `http.corp.domain.example` should now be `https://http.corp.domain.example`).
- Proxy's sign out handler `{}/.pomerium/sign_out` now accepts an optional `redirect_uri` parameter which can be used to specify a custom redirect page, so long as it is under the same top-level domain. [GH-183]
- Policy configuration can now be empty at startup. [GH-190]
- Websocket support is now set per-route instead of globally. [GH-204]
- Golint removed from amd64 container. [GH-215]
- Pomerium will error if a session cookie is over 4096 bytes, instead of failing silently. [GH-212]

### FIXED

- Fixed HEADERS environment variable parsing. [GH-188]
- Fixed Azure group lookups. [GH-190]
- If a session is too large (over 4096 bytes) Pomerium will no longer fail silently. [GH-211]
- Internal URLs like dashboard now start auth process to login a user if no session is found. [GH-205].
- When set,`CookieDomain` lets a user set the scope of the user session. CSRF cookies will still always be scoped at the individual route level. [GH-181]

## v0.0.5

### NEW

- Add ability to detect changes and reload policy configuration files. [GH-150]
- Add user dashboard containing information about the current user's session. [GH-123]
- Add functionality allowing users to initiate manual refresh of their session. This is helpful when a user's access control details are updated but their session hasn't updated yet. To prevent abuse, manual refresh is gated by a cooldown (`REFRESH_COOLDOWN`) which defaults to five minutes. [GH-73]
- Add Administrator (super user) account support (`ADMINISTRATORS`). [GH-110]
- Add feature that allows Administrators to impersonate / sign-in as another user from the user dashboard. [GH-110]
- Add docker images and builds for ARM. [GH-95]
- Add support for public, unauthenticated routes. [GH-129]

### CHANGED

- Add Request ID to error pages. [GH-144]
- Refactor configuration handling to use spf13/viper bringing a variety of additional supported storage formats.[GH-115]
- Changed config `AUTHENTICATE_INTERNAL_URL` to be a URL containing both a valid hostname and schema. [GH-153]
- User state is now maintained and scoped at the domain level vs at the route level. [GH-128]
- Error pages contain a link to sign out from the current user session. [GH-100]
- Removed `LifetimeDeadline` from `sessions.SessionState`.
- Removed favicon specific request handling. [GH-131]
- Headers are now configurable via the `HEADERS` configuration variable. [GH-108]
- Refactored proxy and authenticate services to share the same session state cookie. [GH-131]
- Removed instances of extraneous session state saves. [GH-131]
- Changed default behavior when no session is found. Users are now redirected to login instead of being shown an error page.[GH-131]
- Updated routes such that all http handlers are now wrapped with a standard set of middleware. Headers, request id, loggers, and health checks middleware are now applied to all routes including 4xx and 5xx responses. [GH-116]
- Changed docker images to be built from [distroless](https://github.com/GoogleContainerTools/distroless). This fixed an issue with `nsswitch` [GH-97], includes `ca-certificates` and limits the attack surface area of our images. [GH-101]
- Changed HTTP to HTTPS redirect server to be user configurable via `HTTP_REDIRECT_ADDR`. [GH-103]
- `Content-Security-Policy` hash updated to match new UI assets.

### FIXED

- Fixed websocket support. [GH-151]
- Fixed an issue where policy and routes were being pre-processed incorrectly. [GH-132]
- Fixed an issue where `golint` was not being found in our docker image. [GH-121]

## v0.0.4

### CHANGED

- HTTP [Strict Transport Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) is included by default and set to one year. [GH-92]
- HTTP now redirects to HTTPS. [GH-92]
- Removed extraneous `AUTHORIZE_INTERNAL_URL` config option since authorization has no public http handlers, only a gRPC service endpoint. [GH-93]
- Removed `PROXY_ROOT_DOMAIN` config option which is now inferred from `AUTHENTICATE_SERVICE_URL`. Only callback requests originating from a URL on the same sub-domain are permitted. [GH-83]
- Removed `REDIRECT_URL` config option which is now inferred from `AUTHENTICATE_SERVICE_URL` (e.g. `https://$AUTHENTICATE_SERVICE_URL/oauth2/callback`). [GH-83]

### FIXED

- Fixed a bug in the Google provider implementation where the `refresh_token`. Updated the google implementation to use the new `prompt=consent` oauth2 parameters. Reported and fixed by @chemhack [GH-81]

### DOCUMENTATION

- Added [synology tutorial]. [GH-96]
- Added [certificates documentation]. [GH-79]

## v0.0.3

### FEATURES

- **Authorization** : The authorization module adds support for per-route access policy. In this release we support the most common forms of identity based access policy: `allowed_users`, `allowed_groups`, and `allowed_domains`. In future versions, the authorization module will also support context and device based authorization policy and decisions. See website documentation for more details.
- **Group Support** : The authenticate service now retrieves a user's group membership information during authentication and refresh. This change may require additional identity provider configuration; all of which are described in the [updated docs](https://www.pomerium.io/docs/identity-providers.html). A brief summary of the requirements for each IdP are as follows:

  - Google requires the [Admin SDK](https://developers.google.com/admin-sdk/directory/) to enabled, a service account with properly delegated access, and `IDP_SERVICE_ACCOUNT` to be set to the base64 encoded value of the service account's key file.
  - Okta requires a `groups` claim to be added to both the `id_token` and `access_token`. No additional API calls are made.
  - Microsoft Azure Active Directory requires the application be given an [additional API permission](https://docs.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0), `Directory.Read.All`.
  - Onelogin requires the [groups](https://developers.onelogin.com/openid-connect/scopes) was supplied during authentication and that groups parameter has been mapped. Group membership is validated on refresh with the [user-info api endpoint](https://developers.onelogin.com/openid-connect/api/user-info).

- **WebSocket Support** : With [Go 1.12](https://golang.org/doc/go1.12#net/http/httputil) pomerium automatically proxies WebSocket requests.

### CHANGED

- Added `LOG_LEVEL` config setting that allows for setting the desired minimum log level for an event to be logged. [GH-74]
- Changed `POMERIUM_DEBUG` config setting to just do console-pretty printing. No longer sets log level. [GH-74]
- Updated `generate_wildcard_cert.sh` to generate a elliptic curve 256 cert by default.
- Updated `env.example` to include a `POLICY` setting example.
- Added `IDP_SERVICE_ACCOUNT` to `env.example` .
- Removed `ALLOWED_DOMAINS` settings which has been replaced by `POLICY`. Authorization is now handled by the authorization service and is defined in the policy configuration files.
- Removed `ROUTES` settings which has been replaced by `POLICY`.
- Add refresh endpoint `${url}/.pomerium/refresh` which forces a token refresh and responds with the json result.
- Group membership added to proxy headers (`x-pomerium-authenticated-user-groups`) and (`x-pomerium-jwt-assertion`).
- Default Cookie lifetime (`COOKIE_EXPIRE`) changed from 7 days to 14 hours ~ roughly one business day.
- Moved identity (`authenticate/providers`) into its own internal identity package as third party identity providers are going to authorization details (group membership, user role, etc) in addition to just authentication attributes.
- Removed circuit breaker package. Calls that were previously wrapped with a circuit breaker fall under gRPC timeouts; which are gated by relatively short timeouts.
- Session expiration times are truncated at the second.
- **Removed gitlab provider**. We can't support groups until [this gitlab bug](https://gitlab.com/gitlab-org/gitlab-ce/issues/44435#note_88150387) is fixed.
- Request context is now maintained throughout request-flow via the [context package](https://golang.org/pkg/context/) enabling timeouts, request tracing, and cancellation.

### FIXED

- `http.Server` and `httputil.NewSingleHostReverseProxy` now uses pomerium's logging package instead of the standard library's built in one. [GH-58]

[certificates documentation]: ../docs/topics/certificates.md
[gh-1]: https://github.com/pomerium/pomerium/issues/1
[gh-10]: https://github.com/pomerium/pomerium/issues/10
[gh-100]: https://github.com/pomerium/pomerium/issues/100
[gh-101]: https://github.com/pomerium/pomerium/issues/101
[gh-102]: https://github.com/pomerium/pomerium/issues/102
[gh-103]: https://github.com/pomerium/pomerium/issues/103
[gh-104]: https://github.com/pomerium/pomerium/issues/104
[gh-105]: https://github.com/pomerium/pomerium/issues/105
[gh-106]: https://github.com/pomerium/pomerium/issues/106
[gh-107]: https://github.com/pomerium/pomerium/issues/107
[gh-108]: https://github.com/pomerium/pomerium/issues/108
[gh-109]: https://github.com/pomerium/pomerium/issues/109
[gh-11]: https://github.com/pomerium/pomerium/issues/11
[gh-110]: https://github.com/pomerium/pomerium/issues/110
[gh-111]: https://github.com/pomerium/pomerium/issues/111
[gh-112]: https://github.com/pomerium/pomerium/issues/112
[gh-113]: https://github.com/pomerium/pomerium/issues/113
[gh-114]: https://github.com/pomerium/pomerium/issues/114
[gh-115]: https://github.com/pomerium/pomerium/issues/115
[gh-116]: https://github.com/pomerium/pomerium/issues/116
[gh-117]: https://github.com/pomerium/pomerium/issues/117
[gh-118]: https://github.com/pomerium/pomerium/issues/118
[gh-119]: https://github.com/pomerium/pomerium/issues/119
[gh-12]: https://github.com/pomerium/pomerium/issues/12
[gh-120]: https://github.com/pomerium/pomerium/issues/120
[gh-121]: https://github.com/pomerium/pomerium/issues/121
[gh-122]: https://github.com/pomerium/pomerium/issues/122
[gh-123]: https://github.com/pomerium/pomerium/issues/123
[gh-124]: https://github.com/pomerium/pomerium/issues/124
[gh-125]: https://github.com/pomerium/pomerium/issues/125
[gh-126]: https://github.com/pomerium/pomerium/issues/126
[gh-127]: https://github.com/pomerium/pomerium/issues/127
[gh-128]: https://github.com/pomerium/pomerium/issues/128
[gh-129]: https://github.com/pomerium/pomerium/issues/129
[gh-13]: https://github.com/pomerium/pomerium/issues/13
[gh-130]: https://github.com/pomerium/pomerium/issues/130
[gh-131]: https://github.com/pomerium/pomerium/issues/131
[gh-132]: https://github.com/pomerium/pomerium/issues/132
[gh-133]: https://github.com/pomerium/pomerium/issues/133
[gh-134]: https://github.com/pomerium/pomerium/issues/134
[gh-135]: https://github.com/pomerium/pomerium/issues/135
[gh-136]: https://github.com/pomerium/pomerium/issues/136
[gh-137]: https://github.com/pomerium/pomerium/issues/137
[gh-138]: https://github.com/pomerium/pomerium/issues/138
[gh-139]: https://github.com/pomerium/pomerium/issues/139
[gh-14]: https://github.com/pomerium/pomerium/issues/14
[gh-140]: https://github.com/pomerium/pomerium/issues/140
[gh-141]: https://github.com/pomerium/pomerium/issues/141
[gh-142]: https://github.com/pomerium/pomerium/issues/142
[gh-143]: https://github.com/pomerium/pomerium/issues/143
[gh-144]: https://github.com/pomerium/pomerium/issues/144
[gh-145]: https://github.com/pomerium/pomerium/issues/145
[gh-146]: https://github.com/pomerium/pomerium/issues/146
[gh-147]: https://github.com/pomerium/pomerium/issues/147
[gh-148]: https://github.com/pomerium/pomerium/issues/148
[gh-149]: https://github.com/pomerium/pomerium/issues/149
[gh-15]: https://github.com/pomerium/pomerium/issues/15
[gh-150]: https://github.com/pomerium/pomerium/issues/150
[gh-151]: https://github.com/pomerium/pomerium/issues/151
[gh-152]: https://github.com/pomerium/pomerium/issues/152
[gh-153]: https://github.com/pomerium/pomerium/issues/153
[gh-154]: https://github.com/pomerium/pomerium/issues/154
[gh-155]: https://github.com/pomerium/pomerium/issues/155
[gh-156]: https://github.com/pomerium/pomerium/issues/156
[gh-157]: https://github.com/pomerium/pomerium/issues/157
[gh-158]: https://github.com/pomerium/pomerium/issues/158
[gh-159]: https://github.com/pomerium/pomerium/issues/159
[gh-16]: https://github.com/pomerium/pomerium/issues/16
[gh-160]: https://github.com/pomerium/pomerium/issues/160
[gh-161]: https://github.com/pomerium/pomerium/issues/161
[gh-162]: https://github.com/pomerium/pomerium/issues/162
[gh-163]: https://github.com/pomerium/pomerium/issues/163
[gh-164]: https://github.com/pomerium/pomerium/issues/164
[gh-165]: https://github.com/pomerium/pomerium/issues/165
[gh-166]: https://github.com/pomerium/pomerium/issues/166
[gh-167]: https://github.com/pomerium/pomerium/issues/167
[gh-168]: https://github.com/pomerium/pomerium/issues/168
[gh-169]: https://github.com/pomerium/pomerium/issues/169
[gh-17]: https://github.com/pomerium/pomerium/issues/17
[gh-170]: https://github.com/pomerium/pomerium/issues/170
[gh-171]: https://github.com/pomerium/pomerium/issues/171
[gh-172]: https://github.com/pomerium/pomerium/issues/172
[gh-173]: https://github.com/pomerium/pomerium/issues/173
[gh-174]: https://github.com/pomerium/pomerium/issues/174
[gh-175]: https://github.com/pomerium/pomerium/issues/175
[gh-176]: https://github.com/pomerium/pomerium/issues/176
[gh-177]: https://github.com/pomerium/pomerium/issues/177
[gh-178]: https://github.com/pomerium/pomerium/issues/178
[gh-179]: https://github.com/pomerium/pomerium/issues/179
[gh-18]: https://github.com/pomerium/pomerium/issues/18
[gh-180]: https://github.com/pomerium/pomerium/issues/180
[gh-181]: https://github.com/pomerium/pomerium/issues/181
[gh-182]: https://github.com/pomerium/pomerium/issues/182
[gh-183]: https://github.com/pomerium/pomerium/issues/183
[gh-184]: https://github.com/pomerium/pomerium/issues/184
[gh-185]: https://github.com/pomerium/pomerium/issues/185
[gh-186]: https://github.com/pomerium/pomerium/issues/186
[gh-187]: https://github.com/pomerium/pomerium/issues/187
[gh-188]: https://github.com/pomerium/pomerium/issues/188
[gh-189]: https://github.com/pomerium/pomerium/issues/189
[gh-19]: https://github.com/pomerium/pomerium/issues/19
[gh-190]: https://github.com/pomerium/pomerium/issues/190
[gh-191]: https://github.com/pomerium/pomerium/issues/191
[gh-192]: https://github.com/pomerium/pomerium/issues/192
[gh-193]: https://github.com/pomerium/pomerium/issues/193
[gh-194]: https://github.com/pomerium/pomerium/issues/194
[gh-195]: https://github.com/pomerium/pomerium/issues/195
[gh-196]: https://github.com/pomerium/pomerium/issues/196
[gh-197]: https://github.com/pomerium/pomerium/issues/197
[gh-198]: https://github.com/pomerium/pomerium/issues/198
[gh-199]: https://github.com/pomerium/pomerium/issues/199
[gh-2]: https://github.com/pomerium/pomerium/issues/2
[gh-20]: https://github.com/pomerium/pomerium/issues/20
[gh-200]: https://github.com/pomerium/pomerium/issues/200
[gh-201]: https://github.com/pomerium/pomerium/issues/201
[gh-202]: https://github.com/pomerium/pomerium/issues/202
[gh-203]: https://github.com/pomerium/pomerium/issues/203
[gh-204]: https://github.com/pomerium/pomerium/issues/204
[gh-205]: https://github.com/pomerium/pomerium/issues/205
[gh-206]: https://github.com/pomerium/pomerium/issues/206
[gh-207]: https://github.com/pomerium/pomerium/issues/207
[gh-208]: https://github.com/pomerium/pomerium/issues/208
[gh-209]: https://github.com/pomerium/pomerium/issues/209
[gh-21]: https://github.com/pomerium/pomerium/issues/21
[gh-210]: https://github.com/pomerium/pomerium/issues/210
[gh-211]: https://github.com/pomerium/pomerium/issues/211
[gh-212]: https://github.com/pomerium/pomerium/issues/212
[gh-213]: https://github.com/pomerium/pomerium/issues/213
[gh-214]: https://github.com/pomerium/pomerium/issues/214
[gh-215]: https://github.com/pomerium/pomerium/issues/215
[gh-216]: https://github.com/pomerium/pomerium/issues/216
[gh-217]: https://github.com/pomerium/pomerium/issues/217
[gh-218]: https://github.com/pomerium/pomerium/issues/218
[gh-219]: https://github.com/pomerium/pomerium/issues/219
[gh-22]: https://github.com/pomerium/pomerium/issues/22
[gh-220]: https://github.com/pomerium/pomerium/issues/220
[gh-221]: https://github.com/pomerium/pomerium/issues/221
[gh-222]: https://github.com/pomerium/pomerium/issues/222
[gh-223]: https://github.com/pomerium/pomerium/issues/223
[gh-224]: https://github.com/pomerium/pomerium/issues/224
[gh-225]: https://github.com/pomerium/pomerium/issues/225
[gh-226]: https://github.com/pomerium/pomerium/issues/226
[gh-227]: https://github.com/pomerium/pomerium/issues/227
[gh-228]: https://github.com/pomerium/pomerium/issues/228
[gh-229]: https://github.com/pomerium/pomerium/issues/229
[gh-23]: https://github.com/pomerium/pomerium/issues/23
[gh-230]: https://github.com/pomerium/pomerium/issues/230
[gh-231]: https://github.com/pomerium/pomerium/issues/231
[gh-232]: https://github.com/pomerium/pomerium/issues/232
[gh-233]: https://github.com/pomerium/pomerium/issues/233
[gh-234]: https://github.com/pomerium/pomerium/issues/234
[gh-235]: https://github.com/pomerium/pomerium/issues/235
[gh-236]: https://github.com/pomerium/pomerium/issues/236
[gh-237]: https://github.com/pomerium/pomerium/issues/237
[gh-238]: https://github.com/pomerium/pomerium/issues/238
[gh-239]: https://github.com/pomerium/pomerium/issues/239
[gh-24]: https://github.com/pomerium/pomerium/issues/24
[gh-240]: https://github.com/pomerium/pomerium/issues/240
[gh-241]: https://github.com/pomerium/pomerium/issues/241
[gh-242]: https://github.com/pomerium/pomerium/issues/242
[gh-243]: https://github.com/pomerium/pomerium/issues/243
[gh-244]: https://github.com/pomerium/pomerium/issues/244
[gh-245]: https://github.com/pomerium/pomerium/issues/245
[gh-246]: https://github.com/pomerium/pomerium/issues/246
[gh-247]: https://github.com/pomerium/pomerium/issues/247
[gh-248]: https://github.com/pomerium/pomerium/issues/248
[gh-249]: https://github.com/pomerium/pomerium/issues/249
[gh-25]: https://github.com/pomerium/pomerium/issues/25
[gh-250]: https://github.com/pomerium/pomerium/issues/250
[gh-251]: https://github.com/pomerium/pomerium/issues/251
[gh-252]: https://github.com/pomerium/pomerium/issues/252
[gh-253]: https://github.com/pomerium/pomerium/issues/253
[gh-254]: https://github.com/pomerium/pomerium/issues/254
[gh-255]: https://github.com/pomerium/pomerium/issues/255
[gh-256]: https://github.com/pomerium/pomerium/issues/256
[gh-257]: https://github.com/pomerium/pomerium/issues/257
[gh-258]: https://github.com/pomerium/pomerium/issues/258
[gh-259]: https://github.com/pomerium/pomerium/issues/259
[gh-26]: https://github.com/pomerium/pomerium/issues/26
[gh-260]: https://github.com/pomerium/pomerium/issues/260
[gh-261]: https://github.com/pomerium/pomerium/issues/261
[gh-262]: https://github.com/pomerium/pomerium/issues/262
[gh-263]: https://github.com/pomerium/pomerium/issues/263
[gh-264]: https://github.com/pomerium/pomerium/issues/264
[gh-265]: https://github.com/pomerium/pomerium/issues/265
[gh-266]: https://github.com/pomerium/pomerium/issues/266
[gh-267]: https://github.com/pomerium/pomerium/issues/267
[gh-268]: https://github.com/pomerium/pomerium/issues/268
[gh-269]: https://github.com/pomerium/pomerium/issues/269
[gh-27]: https://github.com/pomerium/pomerium/issues/27
[gh-270]: https://github.com/pomerium/pomerium/issues/270
[gh-271]: https://github.com/pomerium/pomerium/issues/271
[gh-272]: https://github.com/pomerium/pomerium/issues/272
[gh-273]: https://github.com/pomerium/pomerium/issues/273
[gh-274]: https://github.com/pomerium/pomerium/issues/274
[gh-275]: https://github.com/pomerium/pomerium/issues/275
[gh-276]: https://github.com/pomerium/pomerium/issues/276
[gh-277]: https://github.com/pomerium/pomerium/issues/277
[gh-278]: https://github.com/pomerium/pomerium/issues/278
[gh-279]: https://github.com/pomerium/pomerium/issues/279
[gh-28]: https://github.com/pomerium/pomerium/issues/28
[gh-280]: https://github.com/pomerium/pomerium/issues/280
[gh-281]: https://github.com/pomerium/pomerium/issues/281
[gh-282]: https://github.com/pomerium/pomerium/issues/282
[gh-283]: https://github.com/pomerium/pomerium/issues/283
[gh-284]: https://github.com/pomerium/pomerium/issues/284
[gh-285]: https://github.com/pomerium/pomerium/issues/285
[gh-286]: https://github.com/pomerium/pomerium/issues/286
[gh-287]: https://github.com/pomerium/pomerium/issues/287
[gh-288]: https://github.com/pomerium/pomerium/issues/288
[gh-289]: https://github.com/pomerium/pomerium/issues/289
[gh-29]: https://github.com/pomerium/pomerium/issues/29
[gh-290]: https://github.com/pomerium/pomerium/issues/290
[gh-291]: https://github.com/pomerium/pomerium/issues/291
[gh-292]: https://github.com/pomerium/pomerium/issues/292
[gh-293]: https://github.com/pomerium/pomerium/issues/293
[gh-294]: https://github.com/pomerium/pomerium/issues/294
[gh-295]: https://github.com/pomerium/pomerium/issues/295
[gh-296]: https://github.com/pomerium/pomerium/issues/296
[gh-297]: https://github.com/pomerium/pomerium/issues/297
[gh-298]: https://github.com/pomerium/pomerium/issues/298
[gh-299]: https://github.com/pomerium/pomerium/issues/299
[gh-3]: https://github.com/pomerium/pomerium/issues/3
[gh-30]: https://github.com/pomerium/pomerium/issues/30
[gh-300]: https://github.com/pomerium/pomerium/issues/300
[gh-301]: https://github.com/pomerium/pomerium/issues/301
[gh-302]: https://github.com/pomerium/pomerium/issues/302
[gh-303]: https://github.com/pomerium/pomerium/issues/303
[gh-304]: https://github.com/pomerium/pomerium/issues/304
[gh-305]: https://github.com/pomerium/pomerium/issues/305
[gh-306]: https://github.com/pomerium/pomerium/issues/306
[gh-307]: https://github.com/pomerium/pomerium/issues/307
[gh-308]: https://github.com/pomerium/pomerium/issues/308
[gh-309]: https://github.com/pomerium/pomerium/issues/309
[gh-31]: https://github.com/pomerium/pomerium/issues/31
[gh-310]: https://github.com/pomerium/pomerium/issues/310
[gh-311]: https://github.com/pomerium/pomerium/issues/311
[gh-312]: https://github.com/pomerium/pomerium/issues/312
[gh-313]: https://github.com/pomerium/pomerium/issues/313
[gh-314]: https://github.com/pomerium/pomerium/issues/314
[gh-315]: https://github.com/pomerium/pomerium/issues/315
[gh-316]: https://github.com/pomerium/pomerium/issues/316
[gh-317]: https://github.com/pomerium/pomerium/issues/317
[gh-318]: https://github.com/pomerium/pomerium/issues/318
[gh-319]: https://github.com/pomerium/pomerium/issues/319
[gh-32]: https://github.com/pomerium/pomerium/issues/32
[gh-320]: https://github.com/pomerium/pomerium/issues/320
[gh-321]: https://github.com/pomerium/pomerium/issues/321
[gh-322]: https://github.com/pomerium/pomerium/issues/322
[gh-323]: https://github.com/pomerium/pomerium/issues/323
[gh-324]: https://github.com/pomerium/pomerium/issues/324
[gh-325]: https://github.com/pomerium/pomerium/issues/325
[gh-326]: https://github.com/pomerium/pomerium/issues/326
[gh-327]: https://github.com/pomerium/pomerium/issues/327
[gh-328]: https://github.com/pomerium/pomerium/issues/328
[gh-329]: https://github.com/pomerium/pomerium/issues/329
[gh-33]: https://github.com/pomerium/pomerium/issues/33
[gh-330]: https://github.com/pomerium/pomerium/issues/330
[gh-331]: https://github.com/pomerium/pomerium/issues/331
[gh-332]: https://github.com/pomerium/pomerium/issues/332
[gh-333]: https://github.com/pomerium/pomerium/issues/333
[gh-334]: https://github.com/pomerium/pomerium/issues/334
[gh-335]: https://github.com/pomerium/pomerium/issues/335
[gh-336]: https://github.com/pomerium/pomerium/issues/336
[gh-337]: https://github.com/pomerium/pomerium/issues/337
[gh-338]: https://github.com/pomerium/pomerium/issues/338
[gh-339]: https://github.com/pomerium/pomerium/issues/339
[gh-34]: https://github.com/pomerium/pomerium/issues/34
[gh-340]: https://github.com/pomerium/pomerium/issues/340
[gh-341]: https://github.com/pomerium/pomerium/issues/341
[gh-342]: https://github.com/pomerium/pomerium/issues/342
[gh-343]: https://github.com/pomerium/pomerium/issues/343
[gh-344]: https://github.com/pomerium/pomerium/issues/344
[gh-345]: https://github.com/pomerium/pomerium/issues/345
[gh-346]: https://github.com/pomerium/pomerium/issues/346
[gh-347]: https://github.com/pomerium/pomerium/issues/347
[gh-348]: https://github.com/pomerium/pomerium/issues/348
[gh-349]: https://github.com/pomerium/pomerium/issues/349
[gh-35]: https://github.com/pomerium/pomerium/issues/35
[gh-350]: https://github.com/pomerium/pomerium/issues/350
[gh-351]: https://github.com/pomerium/pomerium/issues/351
[gh-352]: https://github.com/pomerium/pomerium/issues/352
[gh-353]: https://github.com/pomerium/pomerium/issues/353
[gh-354]: https://github.com/pomerium/pomerium/issues/354
[gh-355]: https://github.com/pomerium/pomerium/issues/355
[gh-356]: https://github.com/pomerium/pomerium/issues/356
[gh-357]: https://github.com/pomerium/pomerium/issues/357
[gh-358]: https://github.com/pomerium/pomerium/issues/358
[gh-359]: https://github.com/pomerium/pomerium/issues/359
[gh-36]: https://github.com/pomerium/pomerium/issues/36
[gh-360]: https://github.com/pomerium/pomerium/issues/360
[gh-361]: https://github.com/pomerium/pomerium/issues/361
[gh-362]: https://github.com/pomerium/pomerium/issues/362
[gh-363]: https://github.com/pomerium/pomerium/issues/363
[gh-364]: https://github.com/pomerium/pomerium/issues/364
[gh-365]: https://github.com/pomerium/pomerium/issues/365
[gh-366]: https://github.com/pomerium/pomerium/issues/366
[gh-367]: https://github.com/pomerium/pomerium/issues/367
[gh-368]: https://github.com/pomerium/pomerium/issues/368
[gh-369]: https://github.com/pomerium/pomerium/issues/369
[gh-37]: https://github.com/pomerium/pomerium/issues/37
[gh-370]: https://github.com/pomerium/pomerium/issues/370
[gh-371]: https://github.com/pomerium/pomerium/issues/371
[gh-372]: https://github.com/pomerium/pomerium/issues/372
[gh-373]: https://github.com/pomerium/pomerium/issues/373
[gh-374]: https://github.com/pomerium/pomerium/issues/374
[gh-375]: https://github.com/pomerium/pomerium/issues/375
[gh-376]: https://github.com/pomerium/pomerium/issues/376
[gh-377]: https://github.com/pomerium/pomerium/issues/377
[gh-378]: https://github.com/pomerium/pomerium/issues/378
[gh-379]: https://github.com/pomerium/pomerium/issues/379
[gh-38]: https://github.com/pomerium/pomerium/issues/38
[gh-380]: https://github.com/pomerium/pomerium/issues/380
[gh-381]: https://github.com/pomerium/pomerium/issues/381
[gh-382]: https://github.com/pomerium/pomerium/issues/382
[gh-383]: https://github.com/pomerium/pomerium/issues/383
[gh-384]: https://github.com/pomerium/pomerium/issues/384
[gh-385]: https://github.com/pomerium/pomerium/issues/385
[gh-386]: https://github.com/pomerium/pomerium/issues/386
[gh-387]: https://github.com/pomerium/pomerium/issues/387
[gh-388]: https://github.com/pomerium/pomerium/issues/388
[gh-389]: https://github.com/pomerium/pomerium/issues/389
[gh-39]: https://github.com/pomerium/pomerium/issues/39
[gh-390]: https://github.com/pomerium/pomerium/issues/390
[gh-391]: https://github.com/pomerium/pomerium/issues/391
[gh-392]: https://github.com/pomerium/pomerium/issues/392
[gh-393]: https://github.com/pomerium/pomerium/issues/393
[gh-394]: https://github.com/pomerium/pomerium/issues/394
[gh-395]: https://github.com/pomerium/pomerium/issues/395
[gh-396]: https://github.com/pomerium/pomerium/issues/396
[gh-397]: https://github.com/pomerium/pomerium/issues/397
[gh-398]: https://github.com/pomerium/pomerium/issues/398
[gh-399]: https://github.com/pomerium/pomerium/issues/399
[gh-4]: https://github.com/pomerium/pomerium/issues/4
[gh-40]: https://github.com/pomerium/pomerium/issues/40
[gh-400]: https://github.com/pomerium/pomerium/issues/400
[gh-401]: https://github.com/pomerium/pomerium/issues/401
[gh-402]: https://github.com/pomerium/pomerium/issues/402
[gh-403]: https://github.com/pomerium/pomerium/issues/403
[gh-404]: https://github.com/pomerium/pomerium/issues/404
[gh-405]: https://github.com/pomerium/pomerium/issues/405
[gh-406]: https://github.com/pomerium/pomerium/issues/406
[gh-407]: https://github.com/pomerium/pomerium/issues/407
[gh-408]: https://github.com/pomerium/pomerium/issues/408
[gh-409]: https://github.com/pomerium/pomerium/issues/409
[gh-41]: https://github.com/pomerium/pomerium/issues/41
[gh-410]: https://github.com/pomerium/pomerium/issues/410
[gh-411]: https://github.com/pomerium/pomerium/issues/411
[gh-412]: https://github.com/pomerium/pomerium/issues/412
[gh-413]: https://github.com/pomerium/pomerium/issues/413
[gh-414]: https://github.com/pomerium/pomerium/issues/414
[gh-415]: https://github.com/pomerium/pomerium/issues/415
[gh-416]: https://github.com/pomerium/pomerium/issues/416
[gh-417]: https://github.com/pomerium/pomerium/issues/417
[gh-418]: https://github.com/pomerium/pomerium/issues/418
[gh-419]: https://github.com/pomerium/pomerium/issues/419
[gh-42]: https://github.com/pomerium/pomerium/issues/42
[gh-420]: https://github.com/pomerium/pomerium/issues/420
[gh-421]: https://github.com/pomerium/pomerium/issues/421
[gh-422]: https://github.com/pomerium/pomerium/issues/422
[gh-423]: https://github.com/pomerium/pomerium/issues/423
[gh-424]: https://github.com/pomerium/pomerium/issues/424
[gh-425]: https://github.com/pomerium/pomerium/issues/425
[gh-426]: https://github.com/pomerium/pomerium/issues/426
[gh-427]: https://github.com/pomerium/pomerium/issues/427
[gh-428]: https://github.com/pomerium/pomerium/issues/428
[gh-429]: https://github.com/pomerium/pomerium/issues/429
[gh-43]: https://github.com/pomerium/pomerium/issues/43
[gh-430]: https://github.com/pomerium/pomerium/issues/430
[gh-431]: https://github.com/pomerium/pomerium/issues/431
[gh-432]: https://github.com/pomerium/pomerium/issues/432
[gh-433]: https://github.com/pomerium/pomerium/issues/433
[gh-434]: https://github.com/pomerium/pomerium/issues/434
[gh-435]: https://github.com/pomerium/pomerium/issues/435
[gh-436]: https://github.com/pomerium/pomerium/issues/436
[gh-437]: https://github.com/pomerium/pomerium/issues/437
[gh-438]: https://github.com/pomerium/pomerium/issues/438
[gh-439]: https://github.com/pomerium/pomerium/issues/439
[gh-44]: https://github.com/pomerium/pomerium/issues/44
[gh-440]: https://github.com/pomerium/pomerium/issues/440
[gh-441]: https://github.com/pomerium/pomerium/issues/441
[gh-442]: https://github.com/pomerium/pomerium/issues/442
[gh-443]: https://github.com/pomerium/pomerium/issues/443
[gh-444]: https://github.com/pomerium/pomerium/issues/444
[gh-445]: https://github.com/pomerium/pomerium/issues/445
[gh-446]: https://github.com/pomerium/pomerium/issues/446
[gh-447]: https://github.com/pomerium/pomerium/issues/447
[gh-448]: https://github.com/pomerium/pomerium/issues/448
[gh-449]: https://github.com/pomerium/pomerium/issues/449
[gh-45]: https://github.com/pomerium/pomerium/issues/45
[gh-450]: https://github.com/pomerium/pomerium/issues/450
[gh-451]: https://github.com/pomerium/pomerium/issues/451
[gh-452]: https://github.com/pomerium/pomerium/issues/452
[gh-453]: https://github.com/pomerium/pomerium/issues/453
[gh-454]: https://github.com/pomerium/pomerium/issues/454
[gh-455]: https://github.com/pomerium/pomerium/issues/455
[gh-456]: https://github.com/pomerium/pomerium/issues/456
[gh-457]: https://github.com/pomerium/pomerium/issues/457
[gh-458]: https://github.com/pomerium/pomerium/issues/458
[gh-459]: https://github.com/pomerium/pomerium/issues/459
[gh-46]: https://github.com/pomerium/pomerium/issues/46
[gh-460]: https://github.com/pomerium/pomerium/issues/460
[gh-461]: https://github.com/pomerium/pomerium/issues/461
[gh-462]: https://github.com/pomerium/pomerium/issues/462
[gh-463]: https://github.com/pomerium/pomerium/issues/463
[gh-464]: https://github.com/pomerium/pomerium/issues/464
[gh-465]: https://github.com/pomerium/pomerium/issues/465
[gh-466]: https://github.com/pomerium/pomerium/issues/466
[gh-467]: https://github.com/pomerium/pomerium/issues/467
[gh-468]: https://github.com/pomerium/pomerium/issues/468
[gh-469]: https://github.com/pomerium/pomerium/issues/469
[gh-47]: https://github.com/pomerium/pomerium/issues/47
[gh-470]: https://github.com/pomerium/pomerium/issues/470
[gh-471]: https://github.com/pomerium/pomerium/issues/471
[gh-472]: https://github.com/pomerium/pomerium/issues/472
[gh-473]: https://github.com/pomerium/pomerium/issues/473
[gh-474]: https://github.com/pomerium/pomerium/issues/474
[gh-475]: https://github.com/pomerium/pomerium/issues/475
[gh-476]: https://github.com/pomerium/pomerium/issues/476
[gh-477]: https://github.com/pomerium/pomerium/issues/477
[gh-478]: https://github.com/pomerium/pomerium/issues/478
[gh-479]: https://github.com/pomerium/pomerium/issues/479
[gh-48]: https://github.com/pomerium/pomerium/issues/48
[gh-480]: https://github.com/pomerium/pomerium/issues/480
[gh-481]: https://github.com/pomerium/pomerium/issues/481
[gh-482]: https://github.com/pomerium/pomerium/issues/482
[gh-483]: https://github.com/pomerium/pomerium/issues/483
[gh-484]: https://github.com/pomerium/pomerium/issues/484
[gh-485]: https://github.com/pomerium/pomerium/issues/485
[gh-486]: https://github.com/pomerium/pomerium/issues/486
[gh-487]: https://github.com/pomerium/pomerium/issues/487
[gh-488]: https://github.com/pomerium/pomerium/issues/488
[gh-489]: https://github.com/pomerium/pomerium/issues/489
[gh-49]: https://github.com/pomerium/pomerium/issues/49
[gh-490]: https://github.com/pomerium/pomerium/issues/490
[gh-491]: https://github.com/pomerium/pomerium/issues/491
[gh-492]: https://github.com/pomerium/pomerium/issues/492
[gh-493]: https://github.com/pomerium/pomerium/issues/493
[gh-494]: https://github.com/pomerium/pomerium/issues/494
[gh-495]: https://github.com/pomerium/pomerium/issues/495
[gh-496]: https://github.com/pomerium/pomerium/issues/496
[gh-497]: https://github.com/pomerium/pomerium/issues/497
[gh-498]: https://github.com/pomerium/pomerium/issues/498
[gh-499]: https://github.com/pomerium/pomerium/issues/499
[gh-5]: https://github.com/pomerium/pomerium/issues/5
[gh-50]: https://github.com/pomerium/pomerium/issues/50
[gh-500]: https://github.com/pomerium/pomerium/issues/500
[gh-501]: https://github.com/pomerium/pomerium/issues/501
[gh-502]: https://github.com/pomerium/pomerium/issues/502
[gh-503]: https://github.com/pomerium/pomerium/issues/503
[gh-504]: https://github.com/pomerium/pomerium/issues/504
[gh-505]: https://github.com/pomerium/pomerium/issues/505
[gh-506]: https://github.com/pomerium/pomerium/issues/506
[gh-507]: https://github.com/pomerium/pomerium/issues/507
[gh-508]: https://github.com/pomerium/pomerium/issues/508
[gh-509]: https://github.com/pomerium/pomerium/issues/509
[gh-51]: https://github.com/pomerium/pomerium/issues/51
[gh-510]: https://github.com/pomerium/pomerium/issues/510
[gh-511]: https://github.com/pomerium/pomerium/issues/511
[gh-512]: https://github.com/pomerium/pomerium/issues/512
[gh-513]: https://github.com/pomerium/pomerium/issues/513
[gh-514]: https://github.com/pomerium/pomerium/issues/514
[gh-515]: https://github.com/pomerium/pomerium/issues/515
[gh-516]: https://github.com/pomerium/pomerium/issues/516
[gh-517]: https://github.com/pomerium/pomerium/issues/517
[gh-518]: https://github.com/pomerium/pomerium/issues/518
[gh-519]: https://github.com/pomerium/pomerium/issues/519
[gh-52]: https://github.com/pomerium/pomerium/issues/52
[gh-520]: https://github.com/pomerium/pomerium/issues/520
[gh-521]: https://github.com/pomerium/pomerium/issues/521
[gh-522]: https://github.com/pomerium/pomerium/issues/522
[gh-523]: https://github.com/pomerium/pomerium/issues/523
[gh-524]: https://github.com/pomerium/pomerium/issues/524
[gh-525]: https://github.com/pomerium/pomerium/issues/525
[gh-526]: https://github.com/pomerium/pomerium/issues/526
[gh-527]: https://github.com/pomerium/pomerium/issues/527
[gh-528]: https://github.com/pomerium/pomerium/issues/528
[gh-529]: https://github.com/pomerium/pomerium/issues/529
[gh-53]: https://github.com/pomerium/pomerium/issues/53
[gh-530]: https://github.com/pomerium/pomerium/issues/530
[gh-531]: https://github.com/pomerium/pomerium/issues/531
[gh-532]: https://github.com/pomerium/pomerium/issues/532
[gh-533]: https://github.com/pomerium/pomerium/issues/533
[gh-534]: https://github.com/pomerium/pomerium/issues/534
[gh-535]: https://github.com/pomerium/pomerium/issues/535
[gh-536]: https://github.com/pomerium/pomerium/issues/536
[gh-537]: https://github.com/pomerium/pomerium/issues/537
[gh-538]: https://github.com/pomerium/pomerium/issues/538
[gh-539]: https://github.com/pomerium/pomerium/issues/539
[gh-54]: https://github.com/pomerium/pomerium/issues/54
[gh-540]: https://github.com/pomerium/pomerium/issues/540
[gh-541]: https://github.com/pomerium/pomerium/issues/541
[gh-542]: https://github.com/pomerium/pomerium/issues/542
[gh-543]: https://github.com/pomerium/pomerium/issues/543
[gh-544]: https://github.com/pomerium/pomerium/issues/544
[gh-545]: https://github.com/pomerium/pomerium/issues/545
[gh-546]: https://github.com/pomerium/pomerium/issues/546
[gh-547]: https://github.com/pomerium/pomerium/issues/547
[gh-548]: https://github.com/pomerium/pomerium/issues/548
[gh-549]: https://github.com/pomerium/pomerium/issues/549
[gh-55]: https://github.com/pomerium/pomerium/issues/55
[gh-550]: https://github.com/pomerium/pomerium/issues/550
[gh-551]: https://github.com/pomerium/pomerium/issues/551
[gh-552]: https://github.com/pomerium/pomerium/issues/552
[gh-553]: https://github.com/pomerium/pomerium/issues/553
[gh-554]: https://github.com/pomerium/pomerium/issues/554
[gh-555]: https://github.com/pomerium/pomerium/issues/555
[gh-556]: https://github.com/pomerium/pomerium/issues/556
[gh-557]: https://github.com/pomerium/pomerium/issues/557
[gh-558]: https://github.com/pomerium/pomerium/issues/558
[gh-559]: https://github.com/pomerium/pomerium/issues/559
[gh-56]: https://github.com/pomerium/pomerium/issues/56
[gh-560]: https://github.com/pomerium/pomerium/issues/560
[gh-561]: https://github.com/pomerium/pomerium/issues/561
[gh-562]: https://github.com/pomerium/pomerium/issues/562
[gh-563]: https://github.com/pomerium/pomerium/issues/563
[gh-564]: https://github.com/pomerium/pomerium/issues/564
[gh-565]: https://github.com/pomerium/pomerium/issues/565
[gh-566]: https://github.com/pomerium/pomerium/issues/566
[gh-567]: https://github.com/pomerium/pomerium/issues/567
[gh-568]: https://github.com/pomerium/pomerium/issues/568
[gh-569]: https://github.com/pomerium/pomerium/issues/569
[gh-57]: https://github.com/pomerium/pomerium/issues/57
[gh-570]: https://github.com/pomerium/pomerium/issues/570
[gh-571]: https://github.com/pomerium/pomerium/issues/571
[gh-572]: https://github.com/pomerium/pomerium/issues/572
[gh-573]: https://github.com/pomerium/pomerium/issues/573
[gh-574]: https://github.com/pomerium/pomerium/issues/574
[gh-575]: https://github.com/pomerium/pomerium/issues/575
[gh-576]: https://github.com/pomerium/pomerium/issues/576
[gh-577]: https://github.com/pomerium/pomerium/issues/577
[gh-578]: https://github.com/pomerium/pomerium/issues/578
[gh-579]: https://github.com/pomerium/pomerium/issues/579
[gh-58]: https://github.com/pomerium/pomerium/issues/58
[gh-580]: https://github.com/pomerium/pomerium/issues/580
[gh-581]: https://github.com/pomerium/pomerium/issues/581
[gh-582]: https://github.com/pomerium/pomerium/issues/582
[gh-583]: https://github.com/pomerium/pomerium/issues/583
[gh-584]: https://github.com/pomerium/pomerium/issues/584
[gh-585]: https://github.com/pomerium/pomerium/issues/585
[gh-586]: https://github.com/pomerium/pomerium/issues/586
[gh-587]: https://github.com/pomerium/pomerium/issues/587
[gh-588]: https://github.com/pomerium/pomerium/issues/588
[gh-589]: https://github.com/pomerium/pomerium/issues/589
[gh-59]: https://github.com/pomerium/pomerium/issues/59
[gh-590]: https://github.com/pomerium/pomerium/issues/590
[gh-591]: https://github.com/pomerium/pomerium/issues/591
[gh-592]: https://github.com/pomerium/pomerium/issues/592
[gh-593]: https://github.com/pomerium/pomerium/issues/593
[gh-594]: https://github.com/pomerium/pomerium/issues/594
[gh-595]: https://github.com/pomerium/pomerium/issues/595
[gh-596]: https://github.com/pomerium/pomerium/issues/596
[gh-597]: https://github.com/pomerium/pomerium/issues/597
[gh-598]: https://github.com/pomerium/pomerium/issues/598
[gh-599]: https://github.com/pomerium/pomerium/issues/599
[gh-6]: https://github.com/pomerium/pomerium/issues/6
[gh-60]: https://github.com/pomerium/pomerium/issues/60
[gh-600]: https://github.com/pomerium/pomerium/issues/600
[gh-601]: https://github.com/pomerium/pomerium/issues/601
[gh-602]: https://github.com/pomerium/pomerium/issues/602
[gh-603]: https://github.com/pomerium/pomerium/issues/603
[gh-604]: https://github.com/pomerium/pomerium/issues/604
[gh-605]: https://github.com/pomerium/pomerium/issues/605
[gh-606]: https://github.com/pomerium/pomerium/issues/606
[gh-607]: https://github.com/pomerium/pomerium/issues/607
[gh-608]: https://github.com/pomerium/pomerium/issues/608
[gh-609]: https://github.com/pomerium/pomerium/issues/609
[gh-61]: https://github.com/pomerium/pomerium/issues/61
[gh-610]: https://github.com/pomerium/pomerium/issues/610
[gh-611]: https://github.com/pomerium/pomerium/issues/611
[gh-612]: https://github.com/pomerium/pomerium/issues/612
[gh-613]: https://github.com/pomerium/pomerium/issues/613
[gh-614]: https://github.com/pomerium/pomerium/issues/614
[gh-615]: https://github.com/pomerium/pomerium/issues/615
[gh-616]: https://github.com/pomerium/pomerium/issues/616
[gh-617]: https://github.com/pomerium/pomerium/issues/617
[gh-618]: https://github.com/pomerium/pomerium/issues/618
[gh-619]: https://github.com/pomerium/pomerium/issues/619
[gh-62]: https://github.com/pomerium/pomerium/issues/62
[gh-620]: https://github.com/pomerium/pomerium/issues/620
[gh-621]: https://github.com/pomerium/pomerium/issues/621
[gh-622]: https://github.com/pomerium/pomerium/issues/622
[gh-623]: https://github.com/pomerium/pomerium/issues/623
[gh-624]: https://github.com/pomerium/pomerium/issues/624
[gh-625]: https://github.com/pomerium/pomerium/issues/625
[gh-626]: https://github.com/pomerium/pomerium/issues/626
[gh-627]: https://github.com/pomerium/pomerium/issues/627
[gh-628]: https://github.com/pomerium/pomerium/issues/628
[gh-629]: https://github.com/pomerium/pomerium/issues/629
[gh-63]: https://github.com/pomerium/pomerium/issues/63
[gh-630]: https://github.com/pomerium/pomerium/issues/630
[gh-631]: https://github.com/pomerium/pomerium/issues/631
[gh-632]: https://github.com/pomerium/pomerium/issues/632
[gh-633]: https://github.com/pomerium/pomerium/issues/633
[gh-634]: https://github.com/pomerium/pomerium/issues/634
[gh-635]: https://github.com/pomerium/pomerium/issues/635
[gh-636]: https://github.com/pomerium/pomerium/issues/636
[gh-637]: https://github.com/pomerium/pomerium/issues/637
[gh-638]: https://github.com/pomerium/pomerium/issues/638
[gh-639]: https://github.com/pomerium/pomerium/issues/639
[gh-64]: https://github.com/pomerium/pomerium/issues/64
[gh-640]: https://github.com/pomerium/pomerium/issues/640
[gh-641]: https://github.com/pomerium/pomerium/issues/641
[gh-642]: https://github.com/pomerium/pomerium/issues/642
[gh-643]: https://github.com/pomerium/pomerium/issues/643
[gh-644]: https://github.com/pomerium/pomerium/issues/644
[gh-645]: https://github.com/pomerium/pomerium/issues/645
[gh-646]: https://github.com/pomerium/pomerium/issues/646
[gh-647]: https://github.com/pomerium/pomerium/issues/647
[gh-648]: https://github.com/pomerium/pomerium/issues/648
[gh-649]: https://github.com/pomerium/pomerium/issues/649
[gh-65]: https://github.com/pomerium/pomerium/issues/65
[gh-650]: https://github.com/pomerium/pomerium/issues/650
[gh-651]: https://github.com/pomerium/pomerium/issues/651
[gh-652]: https://github.com/pomerium/pomerium/issues/652
[gh-653]: https://github.com/pomerium/pomerium/issues/653
[gh-654]: https://github.com/pomerium/pomerium/issues/654
[gh-655]: https://github.com/pomerium/pomerium/issues/655
[gh-656]: https://github.com/pomerium/pomerium/issues/656
[gh-657]: https://github.com/pomerium/pomerium/issues/657
[gh-658]: https://github.com/pomerium/pomerium/issues/658
[gh-659]: https://github.com/pomerium/pomerium/issues/659
[gh-66]: https://github.com/pomerium/pomerium/issues/66
[gh-660]: https://github.com/pomerium/pomerium/issues/660
[gh-661]: https://github.com/pomerium/pomerium/issues/661
[gh-662]: https://github.com/pomerium/pomerium/issues/662
[gh-663]: https://github.com/pomerium/pomerium/issues/663
[gh-664]: https://github.com/pomerium/pomerium/issues/664
[gh-665]: https://github.com/pomerium/pomerium/issues/665
[gh-666]: https://github.com/pomerium/pomerium/issues/666
[gh-667]: https://github.com/pomerium/pomerium/issues/667
[gh-668]: https://github.com/pomerium/pomerium/issues/668
[gh-669]: https://github.com/pomerium/pomerium/issues/669
[gh-67]: https://github.com/pomerium/pomerium/issues/67
[gh-670]: https://github.com/pomerium/pomerium/issues/670
[gh-671]: https://github.com/pomerium/pomerium/issues/671
[gh-672]: https://github.com/pomerium/pomerium/issues/672
[gh-673]: https://github.com/pomerium/pomerium/issues/673
[gh-674]: https://github.com/pomerium/pomerium/issues/674
[gh-675]: https://github.com/pomerium/pomerium/issues/675
[gh-676]: https://github.com/pomerium/pomerium/issues/676
[gh-677]: https://github.com/pomerium/pomerium/issues/677
[gh-678]: https://github.com/pomerium/pomerium/issues/678
[gh-679]: https://github.com/pomerium/pomerium/issues/679
[gh-68]: https://github.com/pomerium/pomerium/issues/68
[gh-69]: https://github.com/pomerium/pomerium/issues/69
[gh-7]: https://github.com/pomerium/pomerium/issues/7
[gh-70]: https://github.com/pomerium/pomerium/issues/70
[gh-71]: https://github.com/pomerium/pomerium/issues/71
[gh-72]: https://github.com/pomerium/pomerium/issues/72
[gh-73]: https://github.com/pomerium/pomerium/issues/73
[gh-74]: https://github.com/pomerium/pomerium/issues/74
[gh-75]: https://github.com/pomerium/pomerium/issues/75
[gh-76]: https://github.com/pomerium/pomerium/issues/76
[gh-77]: https://github.com/pomerium/pomerium/issues/77
[gh-78]: https://github.com/pomerium/pomerium/issues/78
[gh-79]: https://github.com/pomerium/pomerium/issues/79
[gh-8]: https://github.com/pomerium/pomerium/issues/8
[gh-80]: https://github.com/pomerium/pomerium/issues/80
[gh-81]: https://github.com/pomerium/pomerium/issues/81
[gh-82]: https://github.com/pomerium/pomerium/issues/82
[gh-83]: https://github.com/pomerium/pomerium/issues/83
[gh-84]: https://github.com/pomerium/pomerium/issues/84
[gh-85]: https://github.com/pomerium/pomerium/issues/85
[gh-86]: https://github.com/pomerium/pomerium/issues/86
[gh-87]: https://github.com/pomerium/pomerium/issues/87
[gh-88]: https://github.com/pomerium/pomerium/issues/88
[gh-89]: https://github.com/pomerium/pomerium/issues/89
[gh-9]: https://github.com/pomerium/pomerium/issues/9
[gh-90]: https://github.com/pomerium/pomerium/issues/90
[gh-91]: https://github.com/pomerium/pomerium/issues/91
[gh-92]: https://github.com/pomerium/pomerium/issues/92
[gh-93]: https://github.com/pomerium/pomerium/issues/93
[gh-94]: https://github.com/pomerium/pomerium/issues/94
[gh-95]: https://github.com/pomerium/pomerium/issues/95
[gh-96]: https://github.com/pomerium/pomerium/issues/96
[gh-97]: https://github.com/pomerium/pomerium/issues/97
[gh-98]: https://github.com/pomerium/pomerium/issues/98
[gh-99]: https://github.com/pomerium/pomerium/issues/99
[synology tutorial]: ./quick-start/synology.md
