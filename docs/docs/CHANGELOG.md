# Changelog


## [v0.17.0](https://github.com/pomerium/pomerium/tree/v0.17.0) (2022-03-04)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.16.4...v0.17.0)

## New

- adds pomerium version to the user info endpoint [\#3093](https://github.com/pomerium/pomerium/pull/3093) (@nhayfield)
- grpc: remove ptypes references [\#3078](https://github.com/pomerium/pomerium/pull/3078) (@calebdoxsey)
- userinfo: add webauthn buttons to user info page [\#3075](https://github.com/pomerium/pomerium/pull/3075) (@calebdoxsey)
- Style update for User Info Endpoint [\#3055](https://github.com/pomerium/pomerium/pull/3055) (@nhayfield)
- session: remove unused session state properties [\#3022](https://github.com/pomerium/pomerium/pull/3022) (@calebdoxsey)
- frontend: react+mui [\#3004](https://github.com/pomerium/pomerium/pull/3004) (@calebdoxsey)
- controlplane: add compression middleware [\#3000](https://github.com/pomerium/pomerium/pull/3000) (@calebdoxsey)
- authenticate: fix expiring user info endpoint [\#2976](https://github.com/pomerium/pomerium/pull/2976) (@calebdoxsey)
- last known metric error [\#2974](https://github.com/pomerium/pomerium/pull/2974) (@wasaga)
- directory: save IDP errors to databroker, put event handling in dedicated package [\#2957](https://github.com/pomerium/pomerium/pull/2957) (@calebdoxsey)
- google: support groups for users outside of the organization [\#2950](https://github.com/pomerium/pomerium/pull/2950) (@calebdoxsey)
- return explicit error when directory sync is disabled [\#2949](https://github.com/pomerium/pomerium/pull/2949) (@wasaga)
- authenticate: add device-enrolled page [\#2892](https://github.com/pomerium/pomerium/pull/2892) (@calebdoxsey)
- remove deprecated ioutil usages [\#2877](https://github.com/pomerium/pomerium/pull/2877) (@cfanbo)

## Fixed

- fix link for picture in avatar [\#3066](https://github.com/pomerium/pomerium/pull/3066) (@nhayfield)
- userinfo: fix logout button, add sign out confirm page [\#3058](https://github.com/pomerium/pomerium/pull/3058) (@calebdoxsey)
- config: fix httptest local certificate [\#3056](https://github.com/pomerium/pomerium/pull/3056) (@calebdoxsey)
- proxy: fix error page [\#3020](https://github.com/pomerium/pomerium/pull/3020) (@calebdoxsey)
- auth0: support explicit domains in the service account [\#2980](https://github.com/pomerium/pomerium/pull/2980) (@calebdoxsey)
- config: fix TLS config when address and grpc\_address are the same [\#2975](https://github.com/pomerium/pomerium/pull/2975) (@calebdoxsey)
- deployment: enable goreleaser buildx [\#2968](https://github.com/pomerium/pomerium/pull/2968) (@travisgroth)
- config: fix policy matching for regular expressions [\#2966](https://github.com/pomerium/pomerium/pull/2966) (@calebdoxsey)
- fix: frontend html tag mismatch [\#2954](https://github.com/pomerium/pomerium/pull/2954) (@cfanbo)
- devices: shrink credentials by removing unnecessary data [\#2951](https://github.com/pomerium/pomerium/pull/2951) (@calebdoxsey)
- Remove spurious \</ul\> tags [\#2946](https://github.com/pomerium/pomerium/pull/2946) (@sylr)
- authenticate: support webauthn redirects to non-pomerium domains [\#2936](https://github.com/pomerium/pomerium/pull/2936) (@calebdoxsey)
- webauthn: use absolute URL for delete redirect [\#2935](https://github.com/pomerium/pomerium/pull/2935) (@calebdoxsey)
- authenticate: add callback endpoint [\#2931](https://github.com/pomerium/pomerium/pull/2931) (@calebdoxsey)
- devices: treat undefined device types as any [\#2927](https://github.com/pomerium/pomerium/pull/2927) (@calebdoxsey)
- deployment: fix distroless base arch [\#2925](https://github.com/pomerium/pomerium/pull/2925) (@travisgroth)
- handle device states in deny block, fix default device type [\#2919](https://github.com/pomerium/pomerium/pull/2919) (@calebdoxsey)
- envoy: check certificates for must-staple flag and drop them if they are missing the response [\#2909](https://github.com/pomerium/pomerium/pull/2909) (@calebdoxsey)
- integration: fix default port for verify service [\#2895](https://github.com/pomerium/pomerium/pull/2895) (@calebdoxsey)

## Dependency

- chore\(deps\): bump actions/setup-node from 2 to 3 [\#3089](https://github.com/pomerium/pomerium/pull/3089) (@dependabot[bot])
- chore\(deps\): bump actions/setup-python from 2 to 3 [\#3088](https://github.com/pomerium/pomerium/pull/3088) (@dependabot[bot])
- chore\(deps\): bump mikefarah/yq from 4.20.2 to 4.21.1 [\#3087](https://github.com/pomerium/pomerium/pull/3087) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.69.0 to 0.70.0 [\#3086](https://github.com/pomerium/pomerium/pull/3086) (@dependabot[bot])
- chore\(deps\): bump url-parse from 1.5.7 to 1.5.10 [\#3085](https://github.com/pomerium/pomerium/pull/3085) (@dependabot[bot])
- chore\(deps\): bump prismjs from 1.26.0 to 1.27.0 [\#3084](https://github.com/pomerium/pomerium/pull/3084) (@dependabot[bot])
- deps: bump envoy to v1.20.2 [\#3082](https://github.com/pomerium/pomerium/pull/3082) (@travisgroth)
- chore\(deps\): bump mikefarah/yq from 4.20.1 to 4.20.2 [\#3072](https://github.com/pomerium/pomerium/pull/3072) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.68.0 to 0.69.0 [\#3071](https://github.com/pomerium/pomerium/pull/3071) (@dependabot[bot])
- chore\(deps\): bump github.com/golangci/golangci-lint from 1.44.0 to 1.44.2 [\#3070](https://github.com/pomerium/pomerium/pull/3070) (@dependabot[bot])
- chore\(deps\): bump url-parse from 1.5.1 to 1.5.7 [\#3068](https://github.com/pomerium/pomerium/pull/3068) (@dependabot[bot])
- chore\(deps\): bump github.com/gorilla/websocket from 1.4.2 to 1.5.0 [\#3052](https://github.com/pomerium/pomerium/pull/3052) (@dependabot[bot])
- chore\(deps\): bump mikefarah/yq from 4.18.1 to 4.20.1 [\#3051](https://github.com/pomerium/pomerium/pull/3051) (@dependabot[bot])
- chore\(deps\): bump follow-redirects from 1.14.7 to 1.14.8 [\#3043](https://github.com/pomerium/pomerium/pull/3043) (@dependabot[bot])
- chore\(deps\): bump go.uber.org/zap from 1.20.0 to 1.21.0 [\#3041](https://github.com/pomerium/pomerium/pull/3041) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.37.1 to 0.37.2 [\#3040](https://github.com/pomerium/pomerium/pull/3040) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.66.0 to 0.68.0 [\#3033](https://github.com/pomerium/pomerium/pull/3033) (@dependabot[bot])
- deps: increase yarn network timeout [\#3018](https://github.com/pomerium/pomerium/pull/3018) (@travisgroth)
- chore\(deps\): bump github.com/caddyserver/certmagic from 0.15.2 to 0.15.3 [\#3014](https://github.com/pomerium/pomerium/pull/3014) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.36.1 to 0.37.1 [\#3013](https://github.com/pomerium/pomerium/pull/3013) (@dependabot[bot])
- chore\(deps\): bump github.com/shirou/gopsutil/v3 from 3.21.12 to 3.22.1 [\#3012](https://github.com/pomerium/pomerium/pull/3012) (@dependabot[bot])
- chore\(deps\): bump github.com/mholt/acmez from 1.0.1 to 1.0.2 [\#3011](https://github.com/pomerium/pomerium/pull/3011) (@dependabot[bot])
- chore\(deps\): bump mermaid from 8.12.1 to 8.13.10 [\#3010](https://github.com/pomerium/pomerium/pull/3010) (@dependabot[bot])
- chore\(deps\): bump follow-redirects from 1.14.1 to 1.14.7 [\#3009](https://github.com/pomerium/pomerium/pull/3009) (@dependabot[bot])
- chore\(deps\): bump prismjs from 1.24.1 to 1.26.0 [\#3008](https://github.com/pomerium/pomerium/pull/3008) (@dependabot[bot])
- chore\(deps\): bump mikefarah/yq from 4.17.2 to 4.18.1 [\#2989](https://github.com/pomerium/pomerium/pull/2989) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/grpc from 1.43.0 to 1.44.0 [\#2988](https://github.com/pomerium/pomerium/pull/2988) (@dependabot[bot])
- chore\(deps\): bump github.com/golangci/golangci-lint from 1.43.0 to 1.44.0 [\#2987](https://github.com/pomerium/pomerium/pull/2987) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.65.0 to 0.66.0 [\#2986](https://github.com/pomerium/pomerium/pull/2986) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/client\_golang from 1.12.0 to 1.12.1 [\#2985](https://github.com/pomerium/pomerium/pull/2985) (@dependabot[bot])
- chore\(deps\): bump mikefarah/yq from 4.16.2 to 4.17.2 [\#2963](https://github.com/pomerium/pomerium/pull/2963) (@dependabot[bot])
- chore\(deps\): bump github.com/google/go-cmp from 0.5.6 to 0.5.7 [\#2962](https://github.com/pomerium/pomerium/pull/2962) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/client\_golang from 1.11.0 to 1.12.0 [\#2961](https://github.com/pomerium/pomerium/pull/2961) (@dependabot[bot])
- chore\(deps\): bump github.com/openzipkin/zipkin-go from 0.3.0 to 0.4.0 [\#2942](https://github.com/pomerium/pomerium/pull/2942) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.64.0 to 0.65.0 [\#2941](https://github.com/pomerium/pomerium/pull/2941) (@dependabot[bot])
- chore\(deps\): bump github.com/envoyproxy/protoc-gen-validate from 0.6.2 to 0.6.3 [\#2940](https://github.com/pomerium/pomerium/pull/2940) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.36.0 to 0.36.1 [\#2939](https://github.com/pomerium/pomerium/pull/2939) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.63.0 to 0.64.0 [\#2913](https://github.com/pomerium/pomerium/pull/2913) (@dependabot[bot])
- chore\(deps\): bump go.uber.org/zap from 1.19.1 to 1.20.0 [\#2912](https://github.com/pomerium/pomerium/pull/2912) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.35.0 to 0.36.0 [\#2911](https://github.com/pomerium/pomerium/pull/2911) (@dependabot[bot])
- chore\(deps\): bump github.com/go-chi/chi from 1.5.4 to 4.1.2+incompatible [\#2910](https://github.com/pomerium/pomerium/pull/2910) (@dependabot[bot])
- envoy: upgrade to 1.20.1 [\#2902](https://github.com/pomerium/pomerium/pull/2902) (@calebdoxsey)
- chore\(deps\): bump github.com/shirou/gopsutil/v3 from 3.21.11 to 3.21.12 [\#2886](https://github.com/pomerium/pomerium/pull/2886) (@dependabot[bot])
- chore\(deps\): bump github.com/rs/cors from 1.8.0 to 1.8.2 [\#2855](https://github.com/pomerium/pomerium/pull/2855) (@dependabot[bot])
- chore\(deps\): bump github.com/google/go-jsonnet from 0.17.0 to 0.18.0 [\#2854](https://github.com/pomerium/pomerium/pull/2854) (@dependabot[bot])
- chore\(deps\): bump mikefarah/yq from 4.16.1 to 4.16.2 [\#2853](https://github.com/pomerium/pomerium/pull/2853) (@dependabot[bot])

## Deployment

- deployment: remove DST cert workaround from debug image [\#2958](https://github.com/pomerium/pomerium/pull/2958) (@travisgroth)
- deployment: multi-arch master images [\#2896](https://github.com/pomerium/pomerium/pull/2896) (@travisgroth)

## Changed

- config: add idp\_client\_id and idp\_client\_secret to protobuf [\#3060](https://github.com/pomerium/pomerium/pull/3060) (@calebdoxsey)
- Extract email for active directory users that don't have access to exchange [\#3053](https://github.com/pomerium/pomerium/pull/3053) (@JBodkin-Amphora)
- disable blank github issues [\#2898](https://github.com/pomerium/pomerium/pull/2898) (@travisgroth)

## [v0.16.4](https://github.com/pomerium/pomerium/tree/v0.16.4) (2022-02-25)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.16.3...v0.16.4)

## Dependency

- deps: update envoy to v1.19.3 [\#3083](https://github.com/pomerium/pomerium/pull/3083) (@travisgroth)

## [v0.16.3](https://github.com/pomerium/pomerium/tree/v0.16.3) (2022-02-11)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.16.2...v0.16.3)

## Fixed

- deployment: only include pomerium binary [\#3007](https://github.com/pomerium/pomerium/pull/3007) (@travisgroth)
- auth0: support explicit domains in the service account [\#2996](https://github.com/pomerium/pomerium/pull/2996) (@backport-actions-token[bot])

## [v0.16.2](https://github.com/pomerium/pomerium/tree/v0.16.2) (2022-01-25)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.16.1...v0.16.2)

## Fixed

- config: fix policy matching for regular expressions [\#2969](https://github.com/pomerium/pomerium/pull/2969) (@backport-actions-token[bot])

## [v0.16.1](https://github.com/pomerium/pomerium/tree/v0.16.1) (2022-01-19)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.16.0...v0.16.1)

## Fixed

- webauthn: use absolute URL for delete redirect [\#2937](https://github.com/pomerium/pomerium/pull/2937) (@backport-actions-token[bot])
- handle device states in deny block, fix default device type [\#2924](https://github.com/pomerium/pomerium/pull/2924) (@backport-actions-token[bot])
- integration: fix default port for verify service [\#2908](https://github.com/pomerium/pomerium/pull/2908) (@backport-actions-token[bot])

## [v0.16.0](https://github.com/pomerium/pomerium/tree/v0.16.0) (2021-12-22)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.15.8...v0.16.0)

## Breaking

- identity: only assign `access\_type` uri params to google. [\#2782](https://github.com/pomerium/pomerium/pull/2782) (@desimone)
- tls: fallback to self-signed certificate [\#2760](https://github.com/pomerium/pomerium/pull/2760) (@calebdoxsey)
- github: use GraphQL API to reduce number of API calls for directory sync [\#2715](https://github.com/pomerium/pomerium/pull/2715) (@calebdoxsey)

## New

- more idp metrics [\#2842](https://github.com/pomerium/pomerium/pull/2842) (@wasaga)
- devices: add experimental icon [\#2836](https://github.com/pomerium/pomerium/pull/2836) (@calebdoxsey)
- devices: switch "default" device type to two built-in default device types [\#2835](https://github.com/pomerium/pomerium/pull/2835) (@calebdoxsey)
- dashboard: improve display of device credentials, allow deletion [\#2829](https://github.com/pomerium/pomerium/pull/2829) (@calebdoxsey)
- ppl: add support for http\_path and http\_method [\#2813](https://github.com/pomerium/pomerium/pull/2813) (@calebdoxsey)
- config: add internal service URLs [\#2801](https://github.com/pomerium/pomerium/pull/2801) (@calebdoxsey)
- envoy: add hash policy and routing key for hash-based load balancers [\#2791](https://github.com/pomerium/pomerium/pull/2791) (@calebdoxsey)
- authorize: support X-Pomerium-Authorization in addition to Authorization [\#2780](https://github.com/pomerium/pomerium/pull/2780) (@calebdoxsey)
- envoy: treat configuration errors as fatal [\#2777](https://github.com/pomerium/pomerium/pull/2777) (@calebdoxsey)
- envoy: add support for bind\_config bootstrap options [\#2772](https://github.com/pomerium/pomerium/pull/2772) (@calebdoxsey)
- authenticate: redirect / to /.pomerium/ [\#2770](https://github.com/pomerium/pomerium/pull/2770) (@calebdoxsey)
- device: add type id and credential id to enrollment for easier referencing [\#2749](https://github.com/pomerium/pomerium/pull/2749) (@calebdoxsey)
- databroker: add additional log for config source [\#2718](https://github.com/pomerium/pomerium/pull/2718) (@calebdoxsey)
- grpc: remove peer field from logs [\#2712](https://github.com/pomerium/pomerium/pull/2712) (@calebdoxsey)
- desktop client api [\#2711](https://github.com/pomerium/pomerium/pull/2711) (@wasaga)
- telemetry: improve zipkin error logs [\#2710](https://github.com/pomerium/pomerium/pull/2710) (@calebdoxsey)
- authorize: add support for webauthn device policy enforcement [\#2700](https://github.com/pomerium/pomerium/pull/2700) (@calebdoxsey)
- webauthn: update session to support device credentials per type [\#2699](https://github.com/pomerium/pomerium/pull/2699) (@calebdoxsey)
- ppl: add support for additional data [\#2696](https://github.com/pomerium/pomerium/pull/2696) (@calebdoxsey)
- Add additional ACME CA \(autocert\) options [\#2695](https://github.com/pomerium/pomerium/pull/2695) (@hslatman)
- skip configuration updates to the most recent one [\#2690](https://github.com/pomerium/pomerium/pull/2690) (@wasaga)
- authenticate: add support for webauthn [\#2688](https://github.com/pomerium/pomerium/pull/2688) (@calebdoxsey)
- webauthnutil: add helpers for webauthn [\#2686](https://github.com/pomerium/pomerium/pull/2686) (@calebdoxsey)
- devices: add device protobuf types [\#2682](https://github.com/pomerium/pomerium/pull/2682) (@calebdoxsey)
- cryptutil: add SecureToken [\#2681](https://github.com/pomerium/pomerium/pull/2681) (@calebdoxsey)
- config/envoyconfig: better duplicate message [\#2661](https://github.com/pomerium/pomerium/pull/2661) (@desimone)
- pomerium-cli: add support for a custom browser command [\#2617](https://github.com/pomerium/pomerium/pull/2617) (@calebdoxsey)
- ppl: pass contextual information through policy [\#2612](https://github.com/pomerium/pomerium/pull/2612) (@calebdoxsey)
- add description to service accounts [\#2611](https://github.com/pomerium/pomerium/pull/2611) (@nhayfield)
- DOCS: Add copy button to code snippets [\#2597](https://github.com/pomerium/pomerium/pull/2597) (@alexfornuto)
- pomerium-cli: use cache dir instead of config dir [\#2588](https://github.com/pomerium/pomerium/pull/2588) (@calebdoxsey)
- cli: update tcp log output format [\#2586](https://github.com/pomerium/pomerium/pull/2586) (@travisgroth)
- directory: implement exponential backoff for refresh [\#2570](https://github.com/pomerium/pomerium/pull/2570) (@calebdoxsey)
- google: support provider URL [\#2567](https://github.com/pomerium/pomerium/pull/2567) (@calebdoxsey)
- config: remove signature\_key\_algorithm [\#2557](https://github.com/pomerium/pomerium/pull/2557) (@calebdoxsey)
- allow pomerium to start without certs [\#2555](https://github.com/pomerium/pomerium/pull/2555) (@wasaga)
- integration: kubernetes support [\#2536](https://github.com/pomerium/pomerium/pull/2536) (@calebdoxsey)
- integration: nginx [\#2532](https://github.com/pomerium/pomerium/pull/2532) (@calebdoxsey)
- integration: add traefik tests [\#2530](https://github.com/pomerium/pomerium/pull/2530) (@calebdoxsey)
- envoy: remove deprecated access\_log\_path [\#2523](https://github.com/pomerium/pomerium/pull/2523) (@calebdoxsey)
- config: remove headers [\#2522](https://github.com/pomerium/pomerium/pull/2522) (@calebdoxsey)
- integration: add multi test [\#2519](https://github.com/pomerium/pomerium/pull/2519) (@calebdoxsey)
- Remove api from GitLab defaultScope [\#2518](https://github.com/pomerium/pomerium/pull/2518) (@alexfornuto)
- integration: add single-cluster integration tests [\#2516](https://github.com/pomerium/pomerium/pull/2516) (@calebdoxsey)
- integration: remove tests [\#2514](https://github.com/pomerium/pomerium/pull/2514) (@calebdoxsey)
- github: support provider URL [\#2490](https://github.com/pomerium/pomerium/pull/2490) (@calebdoxsey)
- protoutil: add NewAny method for deterministic serialization [\#2462](https://github.com/pomerium/pomerium/pull/2462) (@calebdoxsey)
- fix go get, improve redis test [\#2450](https://github.com/pomerium/pomerium/pull/2450) (@calebdoxsey)
- all: remove unused handler code [\#2439](https://github.com/pomerium/pomerium/pull/2439) (@desimone)

## Security

- identity: fix user refresh [\#2724](https://github.com/pomerium/pomerium/pull/2724) (@calebdoxsey)
- deps: update envoy to 1.19.1 [\#2526](https://github.com/pomerium/pomerium/pull/2526) (@travisgroth)

## Fixed

- config: allow specifying auto codec type in all-in-one mode [\#2846](https://github.com/pomerium/pomerium/pull/2846) (@calebdoxsey)
- dashboard: add confirmation dialog, fix button in firefox [\#2841](https://github.com/pomerium/pomerium/pull/2841) (@calebdoxsey)
- fix: Fixed return description error [\#2825](https://github.com/pomerium/pomerium/pull/2825) (@cfanbo)
- internal/telemetry: fix grpc server metrics [\#2811](https://github.com/pomerium/pomerium/pull/2811) (@travisgroth)
- Fix IdP client metrics [\#2810](https://github.com/pomerium/pomerium/pull/2810) (@travisgroth)
- envoyconfig: fix tls\_downstream\_client\_ca for non-standard ports [\#2802](https://github.com/pomerium/pomerium/pull/2802) (@calebdoxsey)
- config: detect changes to the kubernetes service account token file [\#2767](https://github.com/pomerium/pomerium/pull/2767) (@calebdoxsey)
- deps: update goreleaser [\#2757](https://github.com/pomerium/pomerium/pull/2757) (@travisgroth)

## Documentation

- add docs for ingress regex path [\#2822](https://github.com/pomerium/pomerium/pull/2822) (@wasaga)
- fix typo in docs [\#2819](https://github.com/pomerium/pomerium/pull/2819) (@wasaga)
- DOCS: add Grafana to Guides index [\#2808](https://github.com/pomerium/pomerium/pull/2808) (@alexfornuto)
- DOCS: Fix indentation in API doc [\#2798](https://github.com/pomerium/pomerium/pull/2798) (@alexfornuto)
- DOCS: Create Consolidated Troubleshooting Guide and Replace FAQ [\#2797](https://github.com/pomerium/pomerium/pull/2797) (@alexfornuto)
- docs: update pomerium-cli location [\#2790](https://github.com/pomerium/pomerium/pull/2790) (@travisgroth)
- Document Pomerium Policy Language [\#2789](https://github.com/pomerium/pomerium/pull/2789) (@backport-actions-token[bot])
- Copy edit to changelog entry [\#2786](https://github.com/pomerium/pomerium/pull/2786) (@alexfornuto)
- Document Pomerium Policy Language [\#2784](https://github.com/pomerium/pomerium/pull/2784) (@alexfornuto)
- Remove forward\_auth\_url from Enterprise [\#2779](https://github.com/pomerium/pomerium/pull/2779) (@alexfornuto)
- Docs: Update Kubernetes Dashboard Guide [\#2759](https://github.com/pomerium/pomerium/pull/2759) (@alexfornuto)
- Docs: Update Securing Kubernetes Guide [\#2758](https://github.com/pomerium/pomerium/pull/2758) (@alexfornuto)
- Docs: Add spdy annotation [\#2747](https://github.com/pomerium/pomerium/pull/2747) (@alexfornuto)
- Docs: Update JWT Verification Guide [\#2746](https://github.com/pomerium/pomerium/pull/2746) (@alexfornuto)
- Docs: Add Grafana Integration Guide [\#2742](https://github.com/pomerium/pomerium/pull/2742) (@alexfornuto)
- Docs: Update Traefik Example Headers [\#2732](https://github.com/pomerium/pomerium/pull/2732) (@alexfornuto)
- Docs: Reference gRPC API Docs [\#2717](https://github.com/pomerium/pomerium/pull/2717) (@alexfornuto)
- Minor fix in routes documentation [\#2714](https://github.com/pomerium/pomerium/pull/2714) (@Kerwood)
- Docs: Update Community Page [\#2713](https://github.com/pomerium/pomerium/pull/2713) (@cmo-pomerium)
- Update architecture.md [\#2701](https://github.com/pomerium/pomerium/pull/2701) (@cmo-pomerium)
- Update create TLS command to quote strings. [\#2694](https://github.com/pomerium/pomerium/pull/2694) (@FutureMatt)
- Docs: Correct Claim Example [\#2689](https://github.com/pomerium/pomerium/pull/2689) (@alexfornuto)
- Fix typo in docs [\#2683](https://github.com/pomerium/pomerium/pull/2683) (@nihaals)
- Fixed 'kubtctl' typo on releases page [\#2673](https://github.com/pomerium/pomerium/pull/2673) (@ChaosInTheCRD)
- add service account redirects [\#2664](https://github.com/pomerium/pomerium/pull/2664) (@alexfornuto)
- DOCS: Standardize Relative Links [\#2651](https://github.com/pomerium/pomerium/pull/2651) (@alexfornuto)
- Docs: cross-reference links between concepts and reference [\#2648](https://github.com/pomerium/pomerium/pull/2648) (@alexfornuto)
- adjust sidebarDepths and document Desktop Client releases [\#2645](https://github.com/pomerium/pomerium/pull/2645) (@backport-actions-token[bot])
- typo [\#2644](https://github.com/pomerium/pomerium/pull/2644) (@alexfornuto)
- adjust sidebarDepths and document Desktop Client releases [\#2643](https://github.com/pomerium/pomerium/pull/2643) (@alexfornuto)
- DOCS: CORS preflight in console [\#2642](https://github.com/pomerium/pomerium/pull/2642) (@alexfornuto)
- DOCS: Collapse IDP Header [\#2641](https://github.com/pomerium/pomerium/pull/2641) (@alexfornuto)
- docs: remove extra word / updated docs link [\#2638](https://github.com/pomerium/pomerium/pull/2638) (@cmo-pomerium)
- Docs: Batch Updates [\#2628](https://github.com/pomerium/pomerium/pull/2628) (@alexfornuto)
- Refresh and Update TCP documentation [\#2627](https://github.com/pomerium/pomerium/pull/2627) (@alexfornuto)
- DOC: Copy edits to Okta IdP doc. [\#2623](https://github.com/pomerium/pomerium/pull/2623) (@alexfornuto)
- Docs/batch link fixes [\#2621](https://github.com/pomerium/pomerium/pull/2621) (@alexfornuto)
- Add redirect for installation [\#2618](https://github.com/pomerium/pomerium/pull/2618) (@alexfornuto)
- Add docs team as a code owner of packages.json [\#2605](https://github.com/pomerium/pomerium/pull/2605) (@alexfornuto)
- Update CODEOWNERS [\#2603](https://github.com/pomerium/pomerium/pull/2603) (@alexfornuto)
- DOCS: Update Enterprise Reference Docs [\#2599](https://github.com/pomerium/pomerium/pull/2599) (@alexfornuto)
- Document Enterprise API [\#2595](https://github.com/pomerium/pomerium/pull/2595) (@alexfornuto)
- docs: rename updated icon image [\#2582](https://github.com/pomerium/pomerium/pull/2582) (@travisgroth)
- docs: add updated icon asset [\#2580](https://github.com/pomerium/pomerium/pull/2580) (@travisgroth)
- Document recovery token generation [\#2579](https://github.com/pomerium/pomerium/pull/2579) (@alexfornuto)
- New Topic Page: Original Request Context [\#2569](https://github.com/pomerium/pomerium/pull/2569) (@alexfornuto)
- docs: enterprise console v0.15.2 changelog [\#2564](https://github.com/pomerium/pomerium/pull/2564) (@travisgroth)
- TCP Client Doc [\#2561](https://github.com/pomerium/pomerium/pull/2561) (@alexfornuto)
- Docs: Fix merged PR [\#2546](https://github.com/pomerium/pomerium/pull/2546) (@alexfornuto)
- docs: enterprise v0.15.1 changelog [\#2542](https://github.com/pomerium/pomerium/pull/2542) (@travisgroth)
- Update Ping Identity IdP  [\#2537](https://github.com/pomerium/pomerium/pull/2537) (@alexfornuto)
- update OneLogin IdP doc [\#2533](https://github.com/pomerium/pomerium/pull/2533) (@alexfornuto)
- Update GitLab IdP doc [\#2520](https://github.com/pomerium/pomerium/pull/2520) (@alexfornuto)
- update GitHub IdP doc [\#2503](https://github.com/pomerium/pomerium/pull/2503) (@alexfornuto)
- Update AWS cognito IdP doc [\#2498](https://github.com/pomerium/pomerium/pull/2498) (@alexfornuto)
- Update Azure IdP Doc [\#2497](https://github.com/pomerium/pomerium/pull/2497) (@alexfornuto)
- Auth0 Doc Refresh [\#2494](https://github.com/pomerium/pomerium/pull/2494) (@alexfornuto)
- Update IdP Overview Page [\#2493](https://github.com/pomerium/pomerium/pull/2493) (@alexfornuto)
- Update Okta IdP doc [\#2491](https://github.com/pomerium/pomerium/pull/2491) (@alexfornuto)
- adjust comment blocking [\#2488](https://github.com/pomerium/pomerium/pull/2488) (@alexfornuto)
- document binding service to 443 [\#2487](https://github.com/pomerium/pomerium/pull/2487) (@alexfornuto)
- docs: use generic email [\#2484](https://github.com/pomerium/pomerium/pull/2484) (@alexfornuto)
- Update Docker Quickstart [\#2482](https://github.com/pomerium/pomerium/pull/2482) (@alexfornuto)
- Wrap mkcert command in quotes [\#2481](https://github.com/pomerium/pomerium/pull/2481) (@alexfornuto)
- Updates to Enterprise Quickstart instructions [\#2480](https://github.com/pomerium/pomerium/pull/2480) (@alexfornuto)
- wrap header example values as inline code. [\#2474](https://github.com/pomerium/pomerium/pull/2474) (@alexfornuto)
- docs: clarify  custom request header limitations [\#2471](https://github.com/pomerium/pomerium/pull/2471) (@desimone)
- Update Helm Instructions [\#2467](https://github.com/pomerium/pomerium/pull/2467) (@alexfornuto)
- docs: update enterprise helm instructions to use main repo [\#2463](https://github.com/pomerium/pomerium/pull/2463) (@travisgroth)
- Document tracing sample rate in console [\#2461](https://github.com/pomerium/pomerium/pull/2461) (@alexfornuto)
- Document moving routes [\#2460](https://github.com/pomerium/pomerium/pull/2460) (@alexfornuto)
- Enterprise Upgrade & Changelog Pages [\#2453](https://github.com/pomerium/pomerium/pull/2453) (@alexfornuto)
- docs: update codeowners [\#2451](https://github.com/pomerium/pomerium/pull/2451) (@travisgroth)
- Update binary install doc [\#2447](https://github.com/pomerium/pomerium/pull/2447) (@alexfornuto)
- docs: update branding, concepts [\#2445](https://github.com/pomerium/pomerium/pull/2445) (@desimone)
- specify expected audience in Console config [\#2442](https://github.com/pomerium/pomerium/pull/2442) (@alexfornuto)
- docs: update default version to v0.15 [\#2437](https://github.com/pomerium/pomerium/pull/2437) (@travisgroth)
- docs: update branding [\#2435](https://github.com/pomerium/pomerium/pull/2435) (@desimone)

## Dependency

- chore\(deps\): bump google.golang.org/api from 0.62.0 to 0.63.0 [\#2834](https://github.com/pomerium/pomerium/pull/2834) (@dependabot[bot])
- chore\(deps\): bump github.com/rs/zerolog from 1.26.0 to 1.26.1 [\#2833](https://github.com/pomerium/pomerium/pull/2833) (@dependabot[bot])
- chore\(deps\): bump github.com/spf13/viper from 1.10.0 to 1.10.1 [\#2832](https://github.com/pomerium/pomerium/pull/2832) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/grpc from 1.42.0 to 1.43.0 [\#2831](https://github.com/pomerium/pomerium/pull/2831) (@dependabot[bot])
- chore\(deps\): bump github.com/docker/docker from 20.10.11+incompatible to 20.10.12+incompatible [\#2817](https://github.com/pomerium/pomerium/pull/2817) (@dependabot[bot])
- chore\(deps\): bump github.com/spf13/viper from 1.9.0 to 1.10.0 [\#2816](https://github.com/pomerium/pomerium/pull/2816) (@dependabot[bot])
- dev build support for darwin-arm64 from envoy tip [\#2815](https://github.com/pomerium/pomerium/pull/2815) (@wasaga)
- chore\(deps\): bump github.com/shirou/gopsutil/v3 from 3.21.10 to 3.21.11 [\#2807](https://github.com/pomerium/pomerium/pull/2807) (@dependabot[bot])
- chore\(deps\): bump github.com/mitchellh/mapstructure from 1.4.2 to 1.4.3 [\#2806](https://github.com/pomerium/pomerium/pull/2806) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.60.0 to 0.61.0 [\#2805](https://github.com/pomerium/pomerium/pull/2805) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.34.2 to 0.35.0 [\#2804](https://github.com/pomerium/pomerium/pull/2804) (@dependabot[bot])
- chore\(deps\): bump mikefarah/yq from 4.15.1 to 4.16.1 [\#2803](https://github.com/pomerium/pomerium/pull/2803) (@dependabot[bot])
- chore\(deps\): bump github.com/ory/dockertest/v3 from 3.8.0 to 3.8.1 [\#2785](https://github.com/pomerium/pomerium/pull/2785) (@dependabot[bot])
- chore\(deps\): bump mikefarah/yq from 4.14.2 to 4.15.1 [\#2783](https://github.com/pomerium/pomerium/pull/2783) (@dependabot[bot])
- chore\(deps\): bump github.com/docker/docker from 20.10.10+incompatible to 20.10.11+incompatible [\#2776](https://github.com/pomerium/pomerium/pull/2776) (@dependabot[bot])
- chore\(deps\): bump coverallsapp/github-action from 1.1.2 to 1.1.3 [\#2775](https://github.com/pomerium/pomerium/pull/2775) (@dependabot[bot])
- chore\(deps\): bump mikefarah/yq from 4.6.3 to 4.14.2 [\#2774](https://github.com/pomerium/pomerium/pull/2774) (@dependabot[bot])
- chore\(deps\): bump github.com/caddyserver/certmagic from 0.15.1 to 0.15.2 [\#2769](https://github.com/pomerium/pomerium/pull/2769) (@dependabot[bot])
- chore\(deps\): bump github.com/cenkalti/backoff/v4 from 4.1.1 to 4.1.2 [\#2768](https://github.com/pomerium/pomerium/pull/2768) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.34.1 to 0.34.2 [\#2765](https://github.com/pomerium/pomerium/pull/2765) (@dependabot[bot])
- chore\(deps\): bump github.com/mholt/acmez from 1.0.0 to 1.0.1 [\#2764](https://github.com/pomerium/pomerium/pull/2764) (@dependabot[bot])
- chore\(deps\): bump gopkg.in/auth0.v5 from 5.21.0 to 5.21.1 [\#2763](https://github.com/pomerium/pomerium/pull/2763) (@dependabot[bot])
- chore\(deps\): bump github.com/golangci/golangci-lint from 1.42.1 to 1.43.0 [\#2756](https://github.com/pomerium/pomerium/pull/2756) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.34.0 to 0.34.1 [\#2755](https://github.com/pomerium/pomerium/pull/2755) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/grpc from 1.41.0 to 1.42.0 [\#2754](https://github.com/pomerium/pomerium/pull/2754) (@dependabot[bot])
- chore\(deps\): bump github.com/rs/zerolog from 1.25.0 to 1.26.0 [\#2753](https://github.com/pomerium/pomerium/pull/2753) (@dependabot[bot])
- chore\(deps\): bump gopkg.in/auth0.v5 from 5.20.0 to 5.21.0 [\#2752](https://github.com/pomerium/pomerium/pull/2752) (@dependabot[bot])
- dependencies: vendor base58, remove shortuuid [\#2739](https://github.com/pomerium/pomerium/pull/2739) (@calebdoxsey)
- chore\(deps\): bump google.golang.org/api from 0.58.0 to 0.60.0 [\#2737](https://github.com/pomerium/pomerium/pull/2737) (@dependabot[bot])
- chore\(deps\): bump github.com/shirou/gopsutil/v3 from 3.21.9 to 3.21.10 [\#2736](https://github.com/pomerium/pomerium/pull/2736) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.33.1 to 0.34.0 [\#2735](https://github.com/pomerium/pomerium/pull/2735) (@dependabot[bot])
- chore\(deps\): bump github.com/openzipkin/zipkin-go from 0.2.5 to 0.3.0 [\#2734](https://github.com/pomerium/pomerium/pull/2734) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/common from 0.31.1 to 0.32.1 [\#2706](https://github.com/pomerium/pomerium/pull/2706) (@dependabot[bot])
- chore\(deps\): bump github.com/docker/docker from 20.10.9+incompatible to 20.10.10+incompatible [\#2705](https://github.com/pomerium/pomerium/pull/2705) (@dependabot[bot])
- chore\(deps\): bump gopkg.in/auth0.v5 from 5.19.2 to 5.20.0 [\#2704](https://github.com/pomerium/pomerium/pull/2704) (@dependabot[bot])
- chore\(deps\): bump github.com/envoyproxy/protoc-gen-validate from 0.6.1 to 0.6.2 [\#2703](https://github.com/pomerium/pomerium/pull/2703) (@dependabot[bot])
- chore\(deps\): bump github.com/caddyserver/certmagic from 0.14.5 to 0.15.1 [\#2685](https://github.com/pomerium/pomerium/pull/2685) (@dependabot[bot])
- chore\(deps\): bump github.com/peterbourgon/ff/v3 from 3.1.0 to 3.1.2 [\#2672](https://github.com/pomerium/pomerium/pull/2672) (@dependabot[bot])
- chore\(deps\): bump github.com/shirou/gopsutil/v3 from 3.21.8 to 3.21.9 [\#2671](https://github.com/pomerium/pomerium/pull/2671) (@dependabot[bot])
- chore\(deps\): bump github.com/docker/docker from 20.10.8+incompatible to 20.10.9+incompatible [\#2670](https://github.com/pomerium/pomerium/pull/2670) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.57.0 to 0.58.0 [\#2660](https://github.com/pomerium/pomerium/pull/2660) (@dependabot[bot])
- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.11.3 to 8.11.4 [\#2659](https://github.com/pomerium/pomerium/pull/2659) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.32.1 to 0.33.1 [\#2658](https://github.com/pomerium/pomerium/pull/2658) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/common from 0.31.0 to 0.31.1 [\#2656](https://github.com/pomerium/pomerium/pull/2656) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.32.0 to 0.32.1 [\#2633](https://github.com/pomerium/pomerium/pull/2633) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/grpc from 1.40.0 to 1.41.0 [\#2632](https://github.com/pomerium/pomerium/pull/2632) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/common from 0.30.0 to 0.31.0 [\#2631](https://github.com/pomerium/pomerium/pull/2631) (@dependabot[bot])
- chore\(deps\): bump sigs.k8s.io/yaml from 1.2.0 to 1.3.0 [\#2630](https://github.com/pomerium/pomerium/pull/2630) (@dependabot[bot])
- chore\(deps\): bump github.com/ory/dockertest/v3 from 3.7.0 to 3.8.0 [\#2629](https://github.com/pomerium/pomerium/pull/2629) (@dependabot[bot])
- chore\(deps\): bump github.com/spf13/viper from 1.8.1 to 1.9.0 [\#2616](https://github.com/pomerium/pomerium/pull/2616) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.56.0 to 0.57.0 [\#2615](https://github.com/pomerium/pomerium/pull/2615) (@dependabot[bot])
- chore\(deps\): bump github.com/coreos/go-oidc/v3 from 3.0.0 to 3.1.0 [\#2614](https://github.com/pomerium/pomerium/pull/2614) (@dependabot[bot])
- bump protoc-validate [\#2606](https://github.com/pomerium/pomerium/pull/2606) (@wasaga)
- chore\(deps\): bump go.uber.org/zap from 1.19.0 to 1.19.1 [\#2592](https://github.com/pomerium/pomerium/pull/2592) (@dependabot[bot])
- chore\(deps\): bump github.com/rs/zerolog from 1.24.0 to 1.25.0 [\#2591](https://github.com/pomerium/pomerium/pull/2591) (@dependabot[bot])
- chore\(deps\): bump github.com/shirou/gopsutil/v3 from 3.21.7 to 3.21.8 [\#2577](https://github.com/pomerium/pomerium/pull/2577) (@dependabot[bot])
- chore\(deps\): bump github.com/golangci/golangci-lint from 1.42.0 to 1.42.1 [\#2576](https://github.com/pomerium/pomerium/pull/2576) (@dependabot[bot])
- chore\(deps\): bump github.com/caddyserver/certmagic from 0.14.4 to 0.14.5 [\#2575](https://github.com/pomerium/pomerium/pull/2575) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.54.0 to 0.56.0 [\#2574](https://github.com/pomerium/pomerium/pull/2574) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.31.0 to 0.32.0 [\#2573](https://github.com/pomerium/pomerium/pull/2573) (@dependabot[bot])
- chore\(deps\): bump github.com/fsnotify/fsnotify from 1.5.0 to 1.5.1 [\#2554](https://github.com/pomerium/pomerium/pull/2554) (@dependabot[bot])
- chore\(deps\): bump github.com/caddyserver/certmagic from 0.14.3 to 0.14.4 [\#2553](https://github.com/pomerium/pomerium/pull/2553) (@dependabot[bot])
- chore\(deps\): bump github.com/rs/zerolog from 1.23.0 to 1.24.0 [\#2552](https://github.com/pomerium/pomerium/pull/2552) (@dependabot[bot])
- chore\(deps\): bump github.com/docker/docker from 20.10.7+incompatible to 20.10.8+incompatible [\#2551](https://github.com/pomerium/pomerium/pull/2551) (@dependabot[bot])
- chore\(deps\): bump github.com/caddyserver/certmagic from 0.14.1 to 0.14.3 [\#2550](https://github.com/pomerium/pomerium/pull/2550) (@dependabot[bot])
- chore\(deps\): bump contrib.go.opencensus.io/exporter/prometheus from 0.3.0 to 0.4.0 [\#2549](https://github.com/pomerium/pomerium/pull/2549) (@dependabot[bot])
- chore\(deps\): bump github.com/cespare/xxhash/v2 from 2.1.1 to 2.1.2 [\#2548](https://github.com/pomerium/pomerium/pull/2548) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/procfs from 0.7.2 to 0.7.3 [\#2512](https://github.com/pomerium/pomerium/pull/2512) (@dependabot[bot])
- chore\(deps\): bump github.com/golangci/golangci-lint from 1.41.1 to 1.42.0 [\#2511](https://github.com/pomerium/pomerium/pull/2511) (@dependabot[bot])
- chore\(deps\): bump github.com/fsnotify/fsnotify from 1.4.9 to 1.5.0 [\#2510](https://github.com/pomerium/pomerium/pull/2510) (@dependabot[bot])
- ci: use go 1.17.x [\#2492](https://github.com/pomerium/pomerium/pull/2492) (@desimone)
- chore\(deps\): bump google.golang.org/grpc from 1.39.1 to 1.40.0 [\#2478](https://github.com/pomerium/pomerium/pull/2478) (@dependabot[bot])
- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.11.2 to 8.11.3 [\#2477](https://github.com/pomerium/pomerium/pull/2477) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.52.0 to 0.54.0 [\#2476](https://github.com/pomerium/pomerium/pull/2476) (@dependabot[bot])
- chore\(deps\): bump go.uber.org/zap from 1.18.1 to 1.19.0 [\#2475](https://github.com/pomerium/pomerium/pull/2475) (@dependabot[bot])
- ci: support darwn/arm64 aka m1 for cli [\#2473](https://github.com/pomerium/pomerium/pull/2473) (@desimone)
- chore\(deps\): bump google.golang.org/grpc from 1.39.0 to 1.39.1 [\#2457](https://github.com/pomerium/pomerium/pull/2457) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/procfs from 0.7.1 to 0.7.2 [\#2456](https://github.com/pomerium/pomerium/pull/2456) (@dependabot[bot])
- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.11.1 to 8.11.2 [\#2455](https://github.com/pomerium/pomerium/pull/2455) (@dependabot[bot])
- Hadolint [\#2363](https://github.com/pomerium/pomerium/pull/2363) (@stephengroat)

## Deployment

- deployment: migrate pomerium-cli automation to new repo [\#2771](https://github.com/pomerium/pomerium/pull/2771) (@travisgroth)
- deployment: remove DST\_Root\_CA\_X3 from docker images [\#2677](https://github.com/pomerium/pomerium/pull/2677) (@travisgroth)
- deployment: update goreleaser syntax [\#2524](https://github.com/pomerium/pomerium/pull/2524) (@travisgroth)

## Changed

- move NewGRPCClientConn to public package [\#2826](https://github.com/pomerium/pomerium/pull/2826) (@wasaga)
- rm cli code [\#2824](https://github.com/pomerium/pomerium/pull/2824) (@wasaga)
- ci: remove hadolint [\#2726](https://github.com/pomerium/pomerium/pull/2726) (@travisgroth)
- ci: ignore multiple run commands [\#2566](https://github.com/pomerium/pomerium/pull/2566) (@travisgroth)
- redirect logo to the marketing site [\#2441](https://github.com/pomerium/pomerium/pull/2441) (@alexfornuto)
- ci: use github app for backport credentials [\#2369](https://github.com/pomerium/pomerium/pull/2369) (@travisgroth)

## [v0.15.8](https://github.com/pomerium/pomerium/tree/v0.15.8) (2021-12-17)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.15.7...v0.15.8)

## Fixed

- authorize: fix nginx infinite redirect [\#2812](https://github.com/pomerium/pomerium/pull/2812) (@calebdoxsey)

## Documentation

- DOCS: add Grafana to Guides index [\#2809](https://github.com/pomerium/pomerium/pull/2809) (@backport-actions-token[bot])
- DOCS: Fix indentation in API doc [\#2799](https://github.com/pomerium/pomerium/pull/2799) (@backport-actions-token[bot])
- Docs: Update Kubernetes Dashboard Guide [\#2795](https://github.com/pomerium/pomerium/pull/2795) (@backport-actions-token[bot])
- Docs: Update Securing Kubernetes Guide [\#2792](https://github.com/pomerium/pomerium/pull/2792) (@backport-actions-token[bot])
- Docs: Update JWT Verification Guide [\#2787](https://github.com/pomerium/pomerium/pull/2787) (@backport-actions-token[bot])

## Dependency

- deps: pin release to latest go version [\#2827](https://github.com/pomerium/pomerium/pull/2827) (@travisgroth)

## [v0.15.7](https://github.com/pomerium/pomerium/tree/v0.15.7) (2021-11-15)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.15.6...v0.15.7)

## Fixed

- autocert: remove log [\#2750](https://github.com/pomerium/pomerium/pull/2750) (@backport-actions-token[bot])

## Security

- identity: fix user refresh [\#2725](https://github.com/pomerium/pomerium/pull/2725) (@backport-actions-token[bot])

## Documentation

- Docs: Add Grafana Integration Guide [\#2762](https://github.com/pomerium/pomerium/pull/2762) (@backport-actions-token[bot])
- Docs: Add spdy annotation [\#2751](https://github.com/pomerium/pomerium/pull/2751) (@backport-actions-token[bot])
- Docs: Ingress Controller [\#2745](https://github.com/pomerium/pomerium/pull/2745) (@backport-actions-token[bot])
- Docs: Update Traefik Example Headers [\#2741](https://github.com/pomerium/pomerium/pull/2741) (@backport-actions-token[bot])
- Docs: Update Community Page [\#2731](https://github.com/pomerium/pomerium/pull/2731) (@backport-actions-token[bot])
- Minor fix in routes documentation [\#2721](https://github.com/pomerium/pomerium/pull/2721) (@backport-actions-token[bot])
- Docs: Reference gRPC API Docs [\#2720](https://github.com/pomerium/pomerium/pull/2720) (@backport-actions-token[bot])
- Update architecture.md [\#2707](https://github.com/pomerium/pomerium/pull/2707) (@backport-actions-token[bot])

## [v0.15.6](https://github.com/pomerium/pomerium/tree/v0.15.6) (2021-11-04)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.15.5...v0.15.6)

## Breaking

- github: use GraphQL API to reduce number of API calls for directory sync [\#2715](https://github.com/pomerium/pomerium/pull/2715) (@calebdoxsey)

## New

- databroker: add additional log for config source [\#2718](https://github.com/pomerium/pomerium/pull/2718) (@calebdoxsey)
- grpc: remove peer field from logs [\#2712](https://github.com/pomerium/pomerium/pull/2712) (@calebdoxsey)
- desktop client api [\#2711](https://github.com/pomerium/pomerium/pull/2711) (@wasaga)
- telemetry: improve zipkin error logs [\#2710](https://github.com/pomerium/pomerium/pull/2710) (@calebdoxsey)
- authorize: add support for webauthn device policy enforcement [\#2700](https://github.com/pomerium/pomerium/pull/2700) (@calebdoxsey)
- webauthn: update session to support device credentials per type [\#2699](https://github.com/pomerium/pomerium/pull/2699) (@calebdoxsey)
- ppl: add support for additional data [\#2696](https://github.com/pomerium/pomerium/pull/2696) (@calebdoxsey)
- Add additional ACME CA \(autocert\) options [\#2695](https://github.com/pomerium/pomerium/pull/2695) (@hslatman)
- skip configuration updates to the most recent one [\#2690](https://github.com/pomerium/pomerium/pull/2690) (@wasaga)
- authenticate: add support for webauthn [\#2688](https://github.com/pomerium/pomerium/pull/2688) (@calebdoxsey)
- webauthnutil: add helpers for webauthn [\#2686](https://github.com/pomerium/pomerium/pull/2686) (@calebdoxsey)
- devices: add device protobuf types [\#2682](https://github.com/pomerium/pomerium/pull/2682) (@calebdoxsey)
- cryptutil: add SecureToken [\#2681](https://github.com/pomerium/pomerium/pull/2681) (@calebdoxsey)
- config/envoyconfig: better duplicate message [\#2661](https://github.com/pomerium/pomerium/pull/2661) (@desimone)
- pomerium-cli: add support for a custom browser command [\#2617](https://github.com/pomerium/pomerium/pull/2617) (@calebdoxsey)
- ppl: pass contextual information through policy [\#2612](https://github.com/pomerium/pomerium/pull/2612) (@calebdoxsey)
- add description to service accounts [\#2611](https://github.com/pomerium/pomerium/pull/2611) (@nhayfield)
- DOCS: Add copy button to code snippets [\#2597](https://github.com/pomerium/pomerium/pull/2597) (@alexfornuto)
- pomerium-cli: use cache dir instead of config dir [\#2588](https://github.com/pomerium/pomerium/pull/2588) (@calebdoxsey)
- cli: update tcp log output format [\#2586](https://github.com/pomerium/pomerium/pull/2586) (@travisgroth)
- directory: implement exponential backoff for refresh [\#2570](https://github.com/pomerium/pomerium/pull/2570) (@calebdoxsey)
- google: support provider URL [\#2567](https://github.com/pomerium/pomerium/pull/2567) (@calebdoxsey)
- allow pomerium to start without certs [\#2555](https://github.com/pomerium/pomerium/pull/2555) (@wasaga)
- integration: kubernetes support [\#2536](https://github.com/pomerium/pomerium/pull/2536) (@calebdoxsey)
- integration: nginx [\#2532](https://github.com/pomerium/pomerium/pull/2532) (@calebdoxsey)
- integration: add traefik tests [\#2530](https://github.com/pomerium/pomerium/pull/2530) (@calebdoxsey)
- envoy: remove deprecated access\_log\_path [\#2523](https://github.com/pomerium/pomerium/pull/2523) (@calebdoxsey)
- config: remove headers [\#2522](https://github.com/pomerium/pomerium/pull/2522) (@calebdoxsey)
- integration: add multi test [\#2519](https://github.com/pomerium/pomerium/pull/2519) (@calebdoxsey)
- Remove api from GitLab defaultScope [\#2518](https://github.com/pomerium/pomerium/pull/2518) (@alexfornuto)
- integration: add single-cluster integration tests [\#2516](https://github.com/pomerium/pomerium/pull/2516) (@calebdoxsey)
- integration: remove tests [\#2514](https://github.com/pomerium/pomerium/pull/2514) (@calebdoxsey)
- github: support provider URL [\#2490](https://github.com/pomerium/pomerium/pull/2490) (@calebdoxsey)
- protoutil: add NewAny method for deterministic serialization [\#2462](https://github.com/pomerium/pomerium/pull/2462) (@calebdoxsey)
- fix go get, improve redis test [\#2450](https://github.com/pomerium/pomerium/pull/2450) (@calebdoxsey)
- all: remove unused handler code [\#2439](https://github.com/pomerium/pomerium/pull/2439) (@desimone)

## Fixed

- deployment: relocate pomerium-cli to /usr/bin [\#2727](https://github.com/pomerium/pomerium/pull/2727) (@travisgroth)
- authenticate: always update user record on login [\#2719](https://github.com/pomerium/pomerium/pull/2719) (@calebdoxsey)
- authenticate: add databroker versions to session cookie [\#2709](https://github.com/pomerium/pomerium/pull/2709) (@calebdoxsey)
- protoc: add xds repo [\#2687](https://github.com/pomerium/pomerium/pull/2687) (@calebdoxsey)
- add host-rewrite options to config.proto [\#2668](https://github.com/pomerium/pomerium/pull/2668) (@wasaga)
- authclient: clone TLS configuration to prevent overriding NextProtos [\#2594](https://github.com/pomerium/pomerium/pull/2594) (@calebdoxsey)
- tcptunnel: force the use of HTTP/1.1 during ALPN [\#2593](https://github.com/pomerium/pomerium/pull/2593) (@calebdoxsey)
- userinfo: format exp, iat and updated\_at [\#2585](https://github.com/pomerium/pomerium/pull/2585) (@calebdoxsey)
- autocert: remove log [\#2584](https://github.com/pomerium/pomerium/pull/2584) (@calebdoxsey)
- authorize: use session.user\_id in headers [\#2571](https://github.com/pomerium/pomerium/pull/2571) (@calebdoxsey)
- ppl: use session.user\_id instead of user.id for user criterion [\#2562](https://github.com/pomerium/pomerium/pull/2562) (@calebdoxsey)
- authorize: fix google cloudrun header audience [\#2558](https://github.com/pomerium/pomerium/pull/2558) (@calebdoxsey)
- authorize: fix X-Pomerium-Claim-Groups [\#2539](https://github.com/pomerium/pomerium/pull/2539) (@calebdoxsey)
- grpc: disable gRPC connection re-use across services [\#2515](https://github.com/pomerium/pomerium/pull/2515) (@calebdoxsey)
- fix forward-auth, logging [\#2509](https://github.com/pomerium/pomerium/pull/2509) (@calebdoxsey)
- grpc: send client traffic through envoy [\#2469](https://github.com/pomerium/pomerium/pull/2469) (@calebdoxsey)
- options: remove refresh\_cooldown, add allow\_spdy to proto [\#2446](https://github.com/pomerium/pomerium/pull/2446) (@calebdoxsey)

## Security

- identity: fix user refresh [\#2724](https://github.com/pomerium/pomerium/pull/2724) (@calebdoxsey)
- deps: update envoy to 1.19.1 [\#2526](https://github.com/pomerium/pomerium/pull/2526) (@travisgroth)

## Documentation

- Docs: Update Traefik Example Headers [\#2732](https://github.com/pomerium/pomerium/pull/2732) (@alexfornuto)
- Docs: Reference gRPC API Docs [\#2717](https://github.com/pomerium/pomerium/pull/2717) (@alexfornuto)
- Minor fix in routes documentation [\#2714](https://github.com/pomerium/pomerium/pull/2714) (@Kerwood)
- Docs: Update Community Page [\#2713](https://github.com/pomerium/pomerium/pull/2713) (@cmo-pomerium)
- Update architecture.md [\#2701](https://github.com/pomerium/pomerium/pull/2701) (@cmo-pomerium)
- Update create TLS command to quote strings. [\#2694](https://github.com/pomerium/pomerium/pull/2694) (@FutureMatt)
- Docs: Correct Claim Example [\#2689](https://github.com/pomerium/pomerium/pull/2689) (@alexfornuto)
- Fix typo in docs [\#2683](https://github.com/pomerium/pomerium/pull/2683) (@nihaals)
- Fixed 'kubtctl' typo on releases page [\#2673](https://github.com/pomerium/pomerium/pull/2673) (@ChaosInTheCRD)
- Docs: Ingress Controller [\#2667](https://github.com/pomerium/pomerium/pull/2667) (@alexfornuto)
- add service account redirects [\#2664](https://github.com/pomerium/pomerium/pull/2664) (@alexfornuto)
- DOCS: Standardize Relative Links [\#2651](https://github.com/pomerium/pomerium/pull/2651) (@alexfornuto)
- Docs: cross-reference links between concepts and reference [\#2648](https://github.com/pomerium/pomerium/pull/2648) (@alexfornuto)
- typo [\#2644](https://github.com/pomerium/pomerium/pull/2644) (@alexfornuto)
- adjust sidebarDepths and document Desktop Client releases [\#2643](https://github.com/pomerium/pomerium/pull/2643) (@alexfornuto)
- DOCS: CORS preflight in console [\#2642](https://github.com/pomerium/pomerium/pull/2642) (@alexfornuto)
- DOCS: Collapse IDP Header [\#2641](https://github.com/pomerium/pomerium/pull/2641) (@alexfornuto)
- docs: remove extra word / updated docs link [\#2638](https://github.com/pomerium/pomerium/pull/2638) (@cmo-pomerium)
- Docs: Batch Updates [\#2628](https://github.com/pomerium/pomerium/pull/2628) (@alexfornuto)
- Refresh and Update TCP documentation [\#2627](https://github.com/pomerium/pomerium/pull/2627) (@alexfornuto)
- DOC: Copy edits to Okta IdP doc. [\#2623](https://github.com/pomerium/pomerium/pull/2623) (@alexfornuto)
- Docs/batch link fixes [\#2621](https://github.com/pomerium/pomerium/pull/2621) (@alexfornuto)
- Add redirect for installation [\#2618](https://github.com/pomerium/pomerium/pull/2618) (@alexfornuto)
- Add docs team as a code owner of packages.json [\#2605](https://github.com/pomerium/pomerium/pull/2605) (@alexfornuto)
- Update CODEOWNERS [\#2603](https://github.com/pomerium/pomerium/pull/2603) (@alexfornuto)
- DOCS: Update Enterprise Reference Docs [\#2599](https://github.com/pomerium/pomerium/pull/2599) (@alexfornuto)
- Document Enterprise API [\#2595](https://github.com/pomerium/pomerium/pull/2595) (@alexfornuto)
- docs: rename updated icon image [\#2582](https://github.com/pomerium/pomerium/pull/2582) (@travisgroth)
- docs: add updated icon asset [\#2580](https://github.com/pomerium/pomerium/pull/2580) (@travisgroth)
- Document recovery token generation [\#2579](https://github.com/pomerium/pomerium/pull/2579) (@alexfornuto)
- New Topic Page: Original Request Context [\#2569](https://github.com/pomerium/pomerium/pull/2569) (@alexfornuto)
- docs: enterprise console v0.15.2 changelog [\#2564](https://github.com/pomerium/pomerium/pull/2564) (@travisgroth)
- TCP Client Doc [\#2561](https://github.com/pomerium/pomerium/pull/2561) (@alexfornuto)
- Docs: Fix merged PR [\#2546](https://github.com/pomerium/pomerium/pull/2546) (@alexfornuto)
- docs: enterprise v0.15.1 changelog [\#2542](https://github.com/pomerium/pomerium/pull/2542) (@travisgroth)
- Update Ping Identity IdP  [\#2537](https://github.com/pomerium/pomerium/pull/2537) (@alexfornuto)
- update OneLogin IdP doc [\#2533](https://github.com/pomerium/pomerium/pull/2533) (@alexfornuto)
- Update GitLab IdP doc [\#2520](https://github.com/pomerium/pomerium/pull/2520) (@alexfornuto)
- update GitHub IdP doc [\#2503](https://github.com/pomerium/pomerium/pull/2503) (@alexfornuto)
- Update AWS cognito IdP doc [\#2498](https://github.com/pomerium/pomerium/pull/2498) (@alexfornuto)
- Update Azure IdP Doc [\#2497](https://github.com/pomerium/pomerium/pull/2497) (@alexfornuto)
- Auth0 Doc Refresh [\#2494](https://github.com/pomerium/pomerium/pull/2494) (@alexfornuto)
- Update IdP Overview Page [\#2493](https://github.com/pomerium/pomerium/pull/2493) (@alexfornuto)
- Update Okta IdP doc [\#2491](https://github.com/pomerium/pomerium/pull/2491) (@alexfornuto)
- adjust comment blocking [\#2488](https://github.com/pomerium/pomerium/pull/2488) (@alexfornuto)
- document binding service to 443 [\#2487](https://github.com/pomerium/pomerium/pull/2487) (@alexfornuto)
- docs: use generic email [\#2484](https://github.com/pomerium/pomerium/pull/2484) (@alexfornuto)
- Update Docker Quickstart [\#2482](https://github.com/pomerium/pomerium/pull/2482) (@alexfornuto)
- Wrap mkcert command in quotes [\#2481](https://github.com/pomerium/pomerium/pull/2481) (@alexfornuto)
- Updates to Enterprise Quickstart instructions [\#2480](https://github.com/pomerium/pomerium/pull/2480) (@alexfornuto)
- wrap header example values as inline code. [\#2474](https://github.com/pomerium/pomerium/pull/2474) (@alexfornuto)
- docs: clarify  custom request header limitations [\#2471](https://github.com/pomerium/pomerium/pull/2471) (@desimone)
- Update Helm Instructions [\#2467](https://github.com/pomerium/pomerium/pull/2467) (@alexfornuto)
- docs: update enterprise helm instructions to use main repo [\#2463](https://github.com/pomerium/pomerium/pull/2463) (@travisgroth)
- Document tracing sample rate in console [\#2461](https://github.com/pomerium/pomerium/pull/2461) (@alexfornuto)
- Document moving routes [\#2460](https://github.com/pomerium/pomerium/pull/2460) (@alexfornuto)
- Enterprise Upgrade & Changelog Pages [\#2453](https://github.com/pomerium/pomerium/pull/2453) (@alexfornuto)
- docs: update codeowners [\#2451](https://github.com/pomerium/pomerium/pull/2451) (@travisgroth)
- Update binary install doc [\#2447](https://github.com/pomerium/pomerium/pull/2447) (@alexfornuto)
- docs: update branding, concepts [\#2445](https://github.com/pomerium/pomerium/pull/2445) (@desimone)
- specify expected audience in Console config [\#2442](https://github.com/pomerium/pomerium/pull/2442) (@alexfornuto)
- docs: update default version to v0.15 [\#2437](https://github.com/pomerium/pomerium/pull/2437) (@travisgroth)
- docs: update branding [\#2435](https://github.com/pomerium/pomerium/pull/2435) (@desimone)

## Dependency

- dependencies: vendor base58, remove shortuuid [\#2739](https://github.com/pomerium/pomerium/pull/2739) (@calebdoxsey)
- chore\(deps\): bump github.com/shirou/gopsutil/v3 from 3.21.9 to 3.21.10 [\#2736](https://github.com/pomerium/pomerium/pull/2736) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.33.1 to 0.34.0 [\#2735](https://github.com/pomerium/pomerium/pull/2735) (@dependabot[bot])
- chore\(deps\): bump github.com/openzipkin/zipkin-go from 0.2.5 to 0.3.0 [\#2734](https://github.com/pomerium/pomerium/pull/2734) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/common from 0.31.1 to 0.32.1 [\#2706](https://github.com/pomerium/pomerium/pull/2706) (@dependabot[bot])
- chore\(deps\): bump github.com/docker/docker from 20.10.9+incompatible to 20.10.10+incompatible [\#2705](https://github.com/pomerium/pomerium/pull/2705) (@dependabot[bot])
- chore\(deps\): bump gopkg.in/auth0.v5 from 5.19.2 to 5.20.0 [\#2704](https://github.com/pomerium/pomerium/pull/2704) (@dependabot[bot])
- chore\(deps\): bump github.com/envoyproxy/protoc-gen-validate from 0.6.1 to 0.6.2 [\#2703](https://github.com/pomerium/pomerium/pull/2703) (@dependabot[bot])
- chore\(deps\): bump github.com/caddyserver/certmagic from 0.14.5 to 0.15.1 [\#2685](https://github.com/pomerium/pomerium/pull/2685) (@dependabot[bot])
- chore\(deps\): bump github.com/peterbourgon/ff/v3 from 3.1.0 to 3.1.2 [\#2672](https://github.com/pomerium/pomerium/pull/2672) (@dependabot[bot])
- chore\(deps\): bump github.com/shirou/gopsutil/v3 from 3.21.8 to 3.21.9 [\#2671](https://github.com/pomerium/pomerium/pull/2671) (@dependabot[bot])
- chore\(deps\): bump github.com/docker/docker from 20.10.8+incompatible to 20.10.9+incompatible [\#2670](https://github.com/pomerium/pomerium/pull/2670) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.57.0 to 0.58.0 [\#2660](https://github.com/pomerium/pomerium/pull/2660) (@dependabot[bot])
- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.11.3 to 8.11.4 [\#2659](https://github.com/pomerium/pomerium/pull/2659) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.32.1 to 0.33.1 [\#2658](https://github.com/pomerium/pomerium/pull/2658) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/common from 0.31.0 to 0.31.1 [\#2656](https://github.com/pomerium/pomerium/pull/2656) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.32.0 to 0.32.1 [\#2633](https://github.com/pomerium/pomerium/pull/2633) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/grpc from 1.40.0 to 1.41.0 [\#2632](https://github.com/pomerium/pomerium/pull/2632) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/common from 0.30.0 to 0.31.0 [\#2631](https://github.com/pomerium/pomerium/pull/2631) (@dependabot[bot])
- chore\(deps\): bump sigs.k8s.io/yaml from 1.2.0 to 1.3.0 [\#2630](https://github.com/pomerium/pomerium/pull/2630) (@dependabot[bot])
- chore\(deps\): bump github.com/ory/dockertest/v3 from 3.7.0 to 3.8.0 [\#2629](https://github.com/pomerium/pomerium/pull/2629) (@dependabot[bot])
- chore\(deps\): bump github.com/spf13/viper from 1.8.1 to 1.9.0 [\#2616](https://github.com/pomerium/pomerium/pull/2616) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.56.0 to 0.57.0 [\#2615](https://github.com/pomerium/pomerium/pull/2615) (@dependabot[bot])
- chore\(deps\): bump github.com/coreos/go-oidc/v3 from 3.0.0 to 3.1.0 [\#2614](https://github.com/pomerium/pomerium/pull/2614) (@dependabot[bot])
- bump protoc-validate [\#2606](https://github.com/pomerium/pomerium/pull/2606) (@wasaga)
- chore\(deps\): bump go.uber.org/zap from 1.19.0 to 1.19.1 [\#2592](https://github.com/pomerium/pomerium/pull/2592) (@dependabot[bot])
- chore\(deps\): bump github.com/rs/zerolog from 1.24.0 to 1.25.0 [\#2591](https://github.com/pomerium/pomerium/pull/2591) (@dependabot[bot])
- chore\(deps\): bump github.com/shirou/gopsutil/v3 from 3.21.7 to 3.21.8 [\#2577](https://github.com/pomerium/pomerium/pull/2577) (@dependabot[bot])
- chore\(deps\): bump github.com/golangci/golangci-lint from 1.42.0 to 1.42.1 [\#2576](https://github.com/pomerium/pomerium/pull/2576) (@dependabot[bot])
- chore\(deps\): bump github.com/caddyserver/certmagic from 0.14.4 to 0.14.5 [\#2575](https://github.com/pomerium/pomerium/pull/2575) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.54.0 to 0.56.0 [\#2574](https://github.com/pomerium/pomerium/pull/2574) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.31.0 to 0.32.0 [\#2573](https://github.com/pomerium/pomerium/pull/2573) (@dependabot[bot])
- chore\(deps\): bump github.com/fsnotify/fsnotify from 1.5.0 to 1.5.1 [\#2554](https://github.com/pomerium/pomerium/pull/2554) (@dependabot[bot])
- chore\(deps\): bump github.com/caddyserver/certmagic from 0.14.3 to 0.14.4 [\#2553](https://github.com/pomerium/pomerium/pull/2553) (@dependabot[bot])
- chore\(deps\): bump github.com/rs/zerolog from 1.23.0 to 1.24.0 [\#2552](https://github.com/pomerium/pomerium/pull/2552) (@dependabot[bot])
- chore\(deps\): bump github.com/docker/docker from 20.10.7+incompatible to 20.10.8+incompatible [\#2551](https://github.com/pomerium/pomerium/pull/2551) (@dependabot[bot])
- chore\(deps\): bump github.com/caddyserver/certmagic from 0.14.1 to 0.14.3 [\#2550](https://github.com/pomerium/pomerium/pull/2550) (@dependabot[bot])
- chore\(deps\): bump contrib.go.opencensus.io/exporter/prometheus from 0.3.0 to 0.4.0 [\#2549](https://github.com/pomerium/pomerium/pull/2549) (@dependabot[bot])
- chore\(deps\): bump github.com/cespare/xxhash/v2 from 2.1.1 to 2.1.2 [\#2548](https://github.com/pomerium/pomerium/pull/2548) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/procfs from 0.7.2 to 0.7.3 [\#2512](https://github.com/pomerium/pomerium/pull/2512) (@dependabot[bot])
- chore\(deps\): bump github.com/golangci/golangci-lint from 1.41.1 to 1.42.0 [\#2511](https://github.com/pomerium/pomerium/pull/2511) (@dependabot[bot])
- chore\(deps\): bump github.com/fsnotify/fsnotify from 1.4.9 to 1.5.0 [\#2510](https://github.com/pomerium/pomerium/pull/2510) (@dependabot[bot])
- ci: use go 1.17.x [\#2492](https://github.com/pomerium/pomerium/pull/2492) (@desimone)
- chore\(deps\): bump google.golang.org/grpc from 1.39.1 to 1.40.0 [\#2478](https://github.com/pomerium/pomerium/pull/2478) (@dependabot[bot])
- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.11.2 to 8.11.3 [\#2477](https://github.com/pomerium/pomerium/pull/2477) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.52.0 to 0.54.0 [\#2476](https://github.com/pomerium/pomerium/pull/2476) (@dependabot[bot])
- chore\(deps\): bump go.uber.org/zap from 1.18.1 to 1.19.0 [\#2475](https://github.com/pomerium/pomerium/pull/2475) (@dependabot[bot])
- ci: support darwn/arm64 aka m1 for cli [\#2473](https://github.com/pomerium/pomerium/pull/2473) (@desimone)
- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.11.1 to 8.11.2 [\#2459](https://github.com/pomerium/pomerium/pull/2459) (@backport-actions-token[bot])
- chore\(deps\): bump google.golang.org/grpc from 1.39.0 to 1.39.1 [\#2457](https://github.com/pomerium/pomerium/pull/2457) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/procfs from 0.7.1 to 0.7.2 [\#2456](https://github.com/pomerium/pomerium/pull/2456) (@dependabot[bot])
- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.11.1 to 8.11.2 [\#2455](https://github.com/pomerium/pomerium/pull/2455) (@dependabot[bot])
- Hadolint [\#2363](https://github.com/pomerium/pomerium/pull/2363) (@stephengroat)

## Deployment

- deployment: remove DST\_Root\_CA\_X3 from docker images [\#2677](https://github.com/pomerium/pomerium/pull/2677) (@travisgroth)
- deployment: update goreleaser syntax [\#2524](https://github.com/pomerium/pomerium/pull/2524) (@travisgroth)

## Changed

- ci: remove hadolint [\#2726](https://github.com/pomerium/pomerium/pull/2726) (@travisgroth)
- ci: ignore multiple run commands [\#2566](https://github.com/pomerium/pomerium/pull/2566) (@travisgroth)
- redirect logo to the marketing site [\#2441](https://github.com/pomerium/pomerium/pull/2441) (@alexfornuto)

## [v0.15.5](https://github.com/pomerium/pomerium/tree/v0.15.5) (2021-10-22)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.15.4...v0.15.5)

## New

- skip configuration updates to the most recent one [\#2692](https://github.com/pomerium/pomerium/pull/2692) (@backport-actions-token[bot])

## Documentation

- Update create TLS command to quote strings. [\#2697](https://github.com/pomerium/pomerium/pull/2697) (@backport-actions-token[bot])
- DOCS: CORS preflight in console [\#2693](https://github.com/pomerium/pomerium/pull/2693) (@backport-actions-token[bot])
- Docs: Correct Claim Example [\#2691](https://github.com/pomerium/pomerium/pull/2691) (@backport-actions-token[bot])
- Fix typo in docs [\#2684](https://github.com/pomerium/pomerium/pull/2684) (@backport-actions-token[bot])

## Deployment

- deployment: remove DST\_Root\_CA\_X3 from docker images [\#2698](https://github.com/pomerium/pomerium/pull/2698) (@travisgroth)

## [v0.15.4](https://github.com/pomerium/pomerium/tree/v0.15.4) (2021-10-14)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.15.3...v0.15.4)

## New

- protoutil: add NewAny method for deterministic serialization [\#2662](https://github.com/pomerium/pomerium/pull/2662) (@backport-actions-token[bot])

## Fixed

- backport: host rewrite [\#2669](https://github.com/pomerium/pomerium/pull/2669) (@wasaga)

## Documentation

- Fixed 'kubtctl' typo on releases page [\#2680](https://github.com/pomerium/pomerium/pull/2680) (@backport-actions-token[bot])
- Refresh and Update TCP documentation [\#2679](https://github.com/pomerium/pomerium/pull/2679) (@backport-actions-token[bot])
- Docs: Ingress Controller [\#2667](https://github.com/pomerium/pomerium/pull/2667) (@alexfornuto)
- add service account redirects [\#2665](https://github.com/pomerium/pomerium/pull/2665) (@backport-actions-token[bot])
- DOCS: Standardize Relative Links \(\#2651\) [\#2654](https://github.com/pomerium/pomerium/pull/2654) (@alexfornuto)
- Docs: cross-reference links between concepts and reference [\#2650](https://github.com/pomerium/pomerium/pull/2650) (@backport-actions-token[bot])
- DOCS: Collapse IDP Header [\#2649](https://github.com/pomerium/pomerium/pull/2649) (@backport-actions-token[bot])
- typo [\#2646](https://github.com/pomerium/pomerium/pull/2646) (@backport-actions-token[bot])
- Docs: Batch Updates [\#2640](https://github.com/pomerium/pomerium/pull/2640) (@backport-actions-token[bot])
- docs: remove extra word / updated docs link [\#2639](https://github.com/pomerium/pomerium/pull/2639) (@backport-actions-token[bot])
- TCP Client Doc [\#2626](https://github.com/pomerium/pomerium/pull/2626) (@backport-actions-token[bot])
- DOC: Copy edits to Okta IdP doc. [\#2625](https://github.com/pomerium/pomerium/pull/2625) (@backport-actions-token[bot])
- DOCS: Update Enterprise Reference Docs [\#2624](https://github.com/pomerium/pomerium/pull/2624) (@backport-actions-token[bot])
- Docs/batch link fixes [\#2622](https://github.com/pomerium/pomerium/pull/2622) (@backport-actions-token[bot])
- Add redirect for installation [\#2620](https://github.com/pomerium/pomerium/pull/2620) (@backport-actions-token[bot])
- Document Enterprise API [\#2619](https://github.com/pomerium/pomerium/pull/2619) (@backport-actions-token[bot])

## [v0.15.3](https://github.com/pomerium/pomerium/tree/v0.15.3) (2021-09-17)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.15.2...v0.15.3)

## New

- cli: update tcp log output format [\#2587](https://github.com/pomerium/pomerium/pull/2587) (@travisgroth)

## Fixed

- backport 2593 and 2594 to 0.15 [\#2598](https://github.com/pomerium/pomerium/pull/2598) (@calebdoxsey)

## Documentation

- Add docs team as a code owner of packages.json [\#2607](https://github.com/pomerium/pomerium/pull/2607) (@backport-actions-token[bot])
- New Topic Page: Original Request Context [\#2602](https://github.com/pomerium/pomerium/pull/2602) (@backport-actions-token[bot])
- Document recovery token generation [\#2601](https://github.com/pomerium/pomerium/pull/2601) (@backport-actions-token[bot])
- DOCS: Add copy button to code snippets [\#2600](https://github.com/pomerium/pomerium/pull/2600) (@backport-actions-token[bot])
- docs: rename updated icon image [\#2583](https://github.com/pomerium/pomerium/pull/2583) (@backport-actions-token[bot])
- docs: add updated icon asset [\#2581](https://github.com/pomerium/pomerium/pull/2581) (@backport-actions-token[bot])

## Changed

- Update CODEOWNERS [\#2604](https://github.com/pomerium/pomerium/pull/2604) (@backport-actions-token[bot])

## [v0.15.2](https://github.com/pomerium/pomerium/tree/v0.15.2) (2021-09-03)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.14.8...v0.15.2)

## New

- allow pomerium to start without certs [\#2556](https://github.com/pomerium/pomerium/pull/2556) (@backport-actions-token[bot])

## Fixed

- authorize: use session.user\_id in headers [\#2572](https://github.com/pomerium/pomerium/pull/2572) (@backport-actions-token[bot])
- ppl: use session.user\_id instead of user.id for user criterion [\#2563](https://github.com/pomerium/pomerium/pull/2563) (@backport-actions-token[bot])
- authorize: fix google cloudrun header audience [\#2560](https://github.com/pomerium/pomerium/pull/2560) (@backport-actions-token[bot])
- authorize: fix X-Pomerium-Claim-Groups [\#2540](https://github.com/pomerium/pomerium/pull/2540) (@backport-actions-token[bot])

## Documentation

- docs: enterprise console v0.15.2 changelog [\#2565](https://github.com/pomerium/pomerium/pull/2565) (@backport-actions-token[bot])
- Docs: Fix merged PR [\#2547](https://github.com/pomerium/pomerium/pull/2547) (@backport-actions-token[bot])
- Update Ping Identity IdP  [\#2545](https://github.com/pomerium/pomerium/pull/2545) (@backport-actions-token[bot])
- update OneLogin IdP doc [\#2544](https://github.com/pomerium/pomerium/pull/2544) (@backport-actions-token[bot])
- docs: enterprise v0.15.1 changelog [\#2543](https://github.com/pomerium/pomerium/pull/2543) (@backport-actions-token[bot])
- Updates to Enterprise Quickstart instructions [\#2531](https://github.com/pomerium/pomerium/pull/2531) (@backport-actions-token[bot])
## [v0.15.0](https://github.com/pomerium/pomerium/tree/v0.15.0) (2021-08-05)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.14.7...v0.15.0)

## Breaking

- config: remove support for ed25519 signing keys [\#2430](https://github.com/pomerium/pomerium/pull/2430) (@calebdoxsey)

## New

- telemetry: add nonce and make explicit ack/nack [\#2434](https://github.com/pomerium/pomerium/pull/2434) (@wasaga)
- authorize: log additional session details [\#2419](https://github.com/pomerium/pomerium/pull/2419) (@calebdoxsey)
- telemetry: try guess hostname or external IP addr for metrics [\#2412](https://github.com/pomerium/pomerium/pull/2412) (@wasaga)
- sessions: add impersonate\_session\_id, remove legacy impersonation [\#2407](https://github.com/pomerium/pomerium/pull/2407) (@calebdoxsey)
- envoyconfig: improvements [\#2402](https://github.com/pomerium/pomerium/pull/2402) (@calebdoxsey)
- config: add support for embedded PPL policy [\#2401](https://github.com/pomerium/pomerium/pull/2401) (@calebdoxsey)
- ppl: remove support for aliases [\#2400](https://github.com/pomerium/pomerium/pull/2400) (@calebdoxsey)
- directory: add logging http client to help with debugging outbound http requests [\#2385](https://github.com/pomerium/pomerium/pull/2385) (@calebdoxsey)
- evaluator: use `cryptutil.Hash` for script spans [\#2384](https://github.com/pomerium/pomerium/pull/2384) (@desimone)
- authorize: add additional tracing for rego evaluation [\#2381](https://github.com/pomerium/pomerium/pull/2381) (@calebdoxsey)
- k8s: add flush-credentials command [\#2379](https://github.com/pomerium/pomerium/pull/2379) (@calebdoxsey)
- urlutil: improve error message for urls with port in path [\#2377](https://github.com/pomerium/pomerium/pull/2377) (@calebdoxsey)
- ci: use revive instead of golint [\#2370](https://github.com/pomerium/pomerium/pull/2370) (@calebdoxsey)
- authorize: remove service account impersonate user id, email and groups [\#2365](https://github.com/pomerium/pomerium/pull/2365) (@calebdoxsey)
- envoyconfig: default zipkin path to / when empty [\#2359](https://github.com/pomerium/pomerium/pull/2359) (@calebdoxsey)
- config: add warning about http URLs [\#2358](https://github.com/pomerium/pomerium/pull/2358) (@calebdoxsey)
- authorize: log service account and impersonation details [\#2354](https://github.com/pomerium/pomerium/pull/2354) (@calebdoxsey)
- tools: add tools.go to pin go run apps [\#2344](https://github.com/pomerium/pomerium/pull/2344) (@calebdoxsey)
- envoyconfig: add bootstrap layered runtime configuration [\#2343](https://github.com/pomerium/pomerium/pull/2343) (@calebdoxsey)
- registry/redis: call publish from within lua function [\#2337](https://github.com/pomerium/pomerium/pull/2337) (@calebdoxsey)

## Fixed

- config: remove grpc server max connection age options [\#2427](https://github.com/pomerium/pomerium/pull/2427) (@calebdoxsey)
- authorize: add sid to JWT claims [\#2420](https://github.com/pomerium/pomerium/pull/2420) (@calebdoxsey)
- disable http/2 for websockets [\#2399](https://github.com/pomerium/pomerium/pull/2399) (@calebdoxsey)
- ci: update gcloud action [\#2393](https://github.com/pomerium/pomerium/pull/2393) (@travisgroth)
- google: remove WithHTTPClient [\#2391](https://github.com/pomerium/pomerium/pull/2391) (@calebdoxsey)
- telemetry: support b3 headers on gRPC server calls [\#2376](https://github.com/pomerium/pomerium/pull/2376) (@calebdoxsey)
- authorize: allow redirects on deny [\#2361](https://github.com/pomerium/pomerium/pull/2361) (@calebdoxsey)
- authorize: decode CheckRequest path for redirect [\#2357](https://github.com/pomerium/pomerium/pull/2357) (@calebdoxsey)
- envoyconfig: only delete cached files, ignore noisy error [\#2356](https://github.com/pomerium/pomerium/pull/2356) (@calebdoxsey)
- envoy: only check for pid with monitor [\#2355](https://github.com/pomerium/pomerium/pull/2355) (@calebdoxsey)
- fix: timeout in protobuf [\#2341](https://github.com/pomerium/pomerium/pull/2341) (@wasaga)
- authorize: support boolean deny results [\#2338](https://github.com/pomerium/pomerium/pull/2338) (@calebdoxsey)

## Security

- envoy: only allow embedding [\#2368](https://github.com/pomerium/pomerium/pull/2368) (@calebdoxsey)

## Documentation

- update v0.15 changelog [\#2436](https://github.com/pomerium/pomerium/pull/2436) (@travisgroth)
- doc updates [\#2433](https://github.com/pomerium/pomerium/pull/2433) (@calebdoxsey)
- Update Console installs to match signing\_key [\#2432](https://github.com/pomerium/pomerium/pull/2432) (@alexfornuto)
- docs/reference: Clarify use of idp\_service\_account [\#2431](https://github.com/pomerium/pomerium/pull/2431) (@the-maldridge)
- docs: clarify device identity, not state via client certs [\#2428](https://github.com/pomerium/pomerium/pull/2428) (@desimone)
- v0.15 release notes [\#2409](https://github.com/pomerium/pomerium/pull/2409) (@travisgroth)
- docs: only secure schemes are supported [\#2408](https://github.com/pomerium/pomerium/pull/2408) (@desimone)
- Installation Docs Restructuring [\#2406](https://github.com/pomerium/pomerium/pull/2406) (@alexfornuto)
- symlink security policy to root of project [\#2396](https://github.com/pomerium/pomerium/pull/2396) (@desimone)
- Enterprise Docs [\#2390](https://github.com/pomerium/pomerium/pull/2390) (@alexfornuto)
- Docs bug fixes [\#2362](https://github.com/pomerium/pomerium/pull/2362) (@alexfornuto)
- Docs sorting [\#2346](https://github.com/pomerium/pomerium/pull/2346) (@alexfornuto)
- Update installation source for mkcert [\#2340](https://github.com/pomerium/pomerium/pull/2340) (@alexfornuto)

## Dependency

- chore\(deps\): bump gopkg.in/auth0.v5 from 5.19.1 to 5.19.2 [\#2422](https://github.com/pomerium/pomerium/pull/2422) (@dependabot[bot])
- chore\(deps\): bump github.com/go-jose/go-jose/v3 from 3.0.0-rc.1 to 3.0.0 [\#2421](https://github.com/pomerium/pomerium/pull/2421) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/common from 0.29.0 to 0.30.0 [\#2417](https://github.com/pomerium/pomerium/pull/2417) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.30.2 to 0.31.0 [\#2416](https://github.com/pomerium/pomerium/pull/2416) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.51.0 to 0.52.0 [\#2415](https://github.com/pomerium/pomerium/pull/2415) (@dependabot[bot])
- chore\(deps\): bump github.com/shirou/gopsutil/v3 from 3.21.6 to 3.21.7 [\#2414](https://github.com/pomerium/pomerium/pull/2414) (@dependabot[bot])
- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.11.0 to 8.11.1 [\#2413](https://github.com/pomerium/pomerium/pull/2413) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/procfs from 0.7.0 to 0.7.1 [\#2395](https://github.com/pomerium/pomerium/pull/2395) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.50.0 to 0.51.0 [\#2394](https://github.com/pomerium/pomerium/pull/2394) (@dependabot[bot])
- chore\(deps\): bump github.com/google/uuid from 1.2.0 to 1.3.0 [\#2374](https://github.com/pomerium/pomerium/pull/2374) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.30.1 to 0.30.2 [\#2373](https://github.com/pomerium/pomerium/pull/2373) (@dependabot[bot])
- ci: convert to FOSSA scan [\#2371](https://github.com/pomerium/pomerium/pull/2371) (@travisgroth)
- chore\(deps\): bump github.com/golangci/golangci-lint from 1.40.1 to 1.41.1 [\#2353](https://github.com/pomerium/pomerium/pull/2353) (@dependabot[bot])
- chore\(deps\): bump github.com/caddyserver/certmagic from 0.14.0 to 0.14.1 [\#2352](https://github.com/pomerium/pomerium/pull/2352) (@dependabot[bot])
- chore\(deps\): bump github.com/rs/cors from 1.7.0 to 1.8.0 [\#2334](https://github.com/pomerium/pomerium/pull/2334) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.49.0 to 0.50.0 [\#2333](https://github.com/pomerium/pomerium/pull/2333) (@dependabot[bot])
- chore\(deps\): upgrade kind action to v1.2.0 [\#2331](https://github.com/pomerium/pomerium/pull/2331) (@travisgroth)
- chore\(deps\): bump github.com/spf13/cobra from 1.1.3 to 1.2.1 [\#2330](https://github.com/pomerium/pomerium/pull/2330) (@dependabot[bot])
- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.10.0 to 8.11.0 [\#2329](https://github.com/pomerium/pomerium/pull/2329) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/procfs from 0.6.0 to 0.7.0 [\#2328](https://github.com/pomerium/pomerium/pull/2328) (@dependabot[bot])
- chore\(deps\): bump github.com/shirou/gopsutil/v3 from 3.21.5 to 3.21.6 [\#2326](https://github.com/pomerium/pomerium/pull/2326) (@dependabot[bot])
- chore\(deps\): bump go.uber.org/zap from 1.17.0 to 1.18.1 [\#2325](https://github.com/pomerium/pomerium/pull/2325) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/grpc from 1.38.0 to 1.39.0 [\#2324](https://github.com/pomerium/pomerium/pull/2324) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.29.4 to 0.30.1 [\#2323](https://github.com/pomerium/pomerium/pull/2323) (@dependabot[bot])

## Changed

- redis: increase timeout on test [\#2425](https://github.com/pomerium/pomerium/pull/2425) (@calebdoxsey)
- build: add envoy files to `make clean` [\#2411](https://github.com/pomerium/pomerium/pull/2411) (@travisgroth)
- envoy: bump to 1.19 [\#2392](https://github.com/pomerium/pomerium/pull/2392) (@travisgroth)
- ci: use github app for backport credentials [\#2369](https://github.com/pomerium/pomerium/pull/2369) (@travisgroth)
- databroker: tests [\#2367](https://github.com/pomerium/pomerium/pull/2367) (@calebdoxsey)
- storage/inmemory: add tests for close behavior [\#2336](https://github.com/pomerium/pomerium/pull/2336) (@calebdoxsey)
- redis: refactor change signal test to be more deterministic [\#2335](https://github.com/pomerium/pomerium/pull/2335) (@calebdoxsey)
## [v0.14.8](https://github.com/pomerium/pomerium/tree/v0.14.8) (2021-08-26)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.15.1...v0.14.8)

## Security

- deps: bump envoy to v0.17.4 [\#2535](https://github.com/pomerium/pomerium/pull/2535) (@travisgroth)

## Documentation

- docs: only secure schemes are supported [\#2410](https://github.com/pomerium/pomerium/pull/2410) (@backport-actions-token[bot])
- Docs bug fixes [\#2364](https://github.com/pomerium/pomerium/pull/2364) (@github-actions[bot])
- Docs backporting [\#2351](https://github.com/pomerium/pomerium/pull/2351) (@alexfornuto)
- docs:  google gcp / workspace instructions [\#2350](https://github.com/pomerium/pomerium/pull/2350) (@github-actions[bot])

## Dependency

- chore\(deps\): upgrade kind action to v1.2.0 \(\#2281\) [\#2366](https://github.com/pomerium/pomerium/pull/2366) (@travisgroth)

## Changed

- ci: update gcloud action [\#2538](https://github.com/pomerium/pomerium/pull/2538) (@backport-actions-token[bot])

## [v0.15.1](https://github.com/pomerium/pomerium/tree/v0.15.1) (2021-08-25)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.15.0...v0.15.1)

## Fixed

- options: remove refresh\_cooldown, add allow\_spdy to proto [\#2448](https://github.com/pomerium/pomerium/pull/2448) (@backport-actions-token[bot])

## Security

- deps: update envoy to 1.19.1 [\#2527](https://github.com/pomerium/pomerium/pull/2527) (@backport-actions-token[bot])

## Documentation

- Update GitLab IdP doc [\#2529](https://github.com/pomerium/pomerium/pull/2529) (@backport-actions-token[bot])
- Remove api from GitLab defaultScope [\#2528](https://github.com/pomerium/pomerium/pull/2528) (@backport-actions-token[bot])
- update GitHub IdP doc [\#2508](https://github.com/pomerium/pomerium/pull/2508) (@backport-actions-token[bot])
- docs: update codeowners [\#2506](https://github.com/pomerium/pomerium/pull/2506) (@backport-actions-token[bot])
- Update Helm Instructions [\#2505](https://github.com/pomerium/pomerium/pull/2505) (@backport-actions-token[bot])
- Update Azure IdP Doc [\#2504](https://github.com/pomerium/pomerium/pull/2504) (@backport-actions-token[bot])
- Update IdP Overview Page [\#2502](https://github.com/pomerium/pomerium/pull/2502) (@backport-actions-token[bot])
- Update AWS cognito IdP doc [\#2501](https://github.com/pomerium/pomerium/pull/2501) (@backport-actions-token[bot])
- Auth0 Doc Refresh [\#2500](https://github.com/pomerium/pomerium/pull/2500) (@backport-actions-token[bot])
- document binding service to 443 [\#2499](https://github.com/pomerium/pomerium/pull/2499) (@backport-actions-token[bot])
- Update Okta IdP doc [\#2495](https://github.com/pomerium/pomerium/pull/2495) (@backport-actions-token[bot])
- adjust comment blocking [\#2489](https://github.com/pomerium/pomerium/pull/2489) (@backport-actions-token[bot])
- Update Docker Quickstart \(\#2482\) [\#2486](https://github.com/pomerium/pomerium/pull/2486) (@alexfornuto)
- docs: use generic email [\#2485](https://github.com/pomerium/pomerium/pull/2485) (@backport-actions-token[bot])
- wrap header example values as inline code. [\#2479](https://github.com/pomerium/pomerium/pull/2479) (@backport-actions-token[bot])
- docs: clarify  custom request header limitations [\#2472](https://github.com/pomerium/pomerium/pull/2472) (@backport-actions-token[bot])
- Document moving routes [\#2466](https://github.com/pomerium/pomerium/pull/2466) (@backport-actions-token[bot])
- Document tracing sample rate in console [\#2465](https://github.com/pomerium/pomerium/pull/2465) (@backport-actions-token[bot])
- docs: update enterprise helm instructions to use main repo [\#2464](https://github.com/pomerium/pomerium/pull/2464) (@backport-actions-token[bot])
- Enterprise Upgrade & Changelog Pages [\#2458](https://github.com/pomerium/pomerium/pull/2458) (@backport-actions-token[bot])
- Update binary install doc [\#2452](https://github.com/pomerium/pomerium/pull/2452) (@backport-actions-token[bot])
- docs: update branding, concepts [\#2449](https://github.com/pomerium/pomerium/pull/2449) (@backport-actions-token[bot])
- specify expected audience in Console config [\#2444](https://github.com/pomerium/pomerium/pull/2444) (@backport-actions-token[bot])
- redirect logo to the marketing site [\#2443](https://github.com/pomerium/pomerium/pull/2443) (@backport-actions-token[bot])
- docs: update branding [\#2440](https://github.com/pomerium/pomerium/pull/2440) (@backport-actions-token[bot])
- docs: update default version to v0.15 [\#2438](https://github.com/pomerium/pomerium/pull/2438) (@backport-actions-token[bot])

## Dependency

- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.11.1 to 8.11.2 [\#2459](https://github.com/pomerium/pomerium/pull/2459) (@backport-actions-token[bot])

## Deployment

- deployment: update goreleaser syntax [\#2525](https://github.com/pomerium/pomerium/pull/2525) (@backport-actions-token[bot])
- ci: support darwn/arm64 aka m1 for cli [\#2521](https://github.com/pomerium/pomerium/pull/2521) (@travisgroth)

## [v0.15.0](https://github.com/pomerium/pomerium/tree/v0.15.0) (2021-08-05)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.14.7...v0.15.0)

## Breaking

- config: remove support for ed25519 signing keys [\#2430](https://github.com/pomerium/pomerium/pull/2430) (@calebdoxsey)

## New

- telemetry: add nonce and make explicit ack/nack [\#2434](https://github.com/pomerium/pomerium/pull/2434) (@wasaga)
- authorize: log additional session details [\#2419](https://github.com/pomerium/pomerium/pull/2419) (@calebdoxsey)
- telemetry: try guess hostname or external IP addr for metrics [\#2412](https://github.com/pomerium/pomerium/pull/2412) (@wasaga)
- sessions: add impersonate\_session\_id, remove legacy impersonation [\#2407](https://github.com/pomerium/pomerium/pull/2407) (@calebdoxsey)
- envoyconfig: improvements [\#2402](https://github.com/pomerium/pomerium/pull/2402) (@calebdoxsey)
- config: add support for embedded PPL policy [\#2401](https://github.com/pomerium/pomerium/pull/2401) (@calebdoxsey)
- ppl: remove support for aliases [\#2400](https://github.com/pomerium/pomerium/pull/2400) (@calebdoxsey)
- directory: add logging http client to help with debugging outbound http requests [\#2385](https://github.com/pomerium/pomerium/pull/2385) (@calebdoxsey)
- evaluator: use `cryptutil.Hash` for script spans [\#2384](https://github.com/pomerium/pomerium/pull/2384) (@desimone)
- authorize: add additional tracing for rego evaluation [\#2381](https://github.com/pomerium/pomerium/pull/2381) (@calebdoxsey)
- k8s: add flush-credentials command [\#2379](https://github.com/pomerium/pomerium/pull/2379) (@calebdoxsey)
- urlutil: improve error message for urls with port in path [\#2377](https://github.com/pomerium/pomerium/pull/2377) (@calebdoxsey)
- ci: use revive instead of golint [\#2370](https://github.com/pomerium/pomerium/pull/2370) (@calebdoxsey)
- authorize: remove service account impersonate user id, email and groups [\#2365](https://github.com/pomerium/pomerium/pull/2365) (@calebdoxsey)
- envoyconfig: default zipkin path to / when empty [\#2359](https://github.com/pomerium/pomerium/pull/2359) (@calebdoxsey)
- config: add warning about http URLs [\#2358](https://github.com/pomerium/pomerium/pull/2358) (@calebdoxsey)
- authorize: log service account and impersonation details [\#2354](https://github.com/pomerium/pomerium/pull/2354) (@calebdoxsey)
- tools: add tools.go to pin go run apps [\#2344](https://github.com/pomerium/pomerium/pull/2344) (@calebdoxsey)
- envoyconfig: add bootstrap layered runtime configuration [\#2343](https://github.com/pomerium/pomerium/pull/2343) (@calebdoxsey)
- registry/redis: call publish from within lua function [\#2337](https://github.com/pomerium/pomerium/pull/2337) (@calebdoxsey)
- proxy: add idle timeout [\#2319](https://github.com/pomerium/pomerium/pull/2319) (@wasaga)
- cli: use proxy from environment [\#2316](https://github.com/pomerium/pomerium/pull/2316) (@tskinn)
- authorize: do not send redirects to gRPC  [\#2314](https://github.com/pomerium/pomerium/pull/2314) (@wasaga)
- certs: reject certs from databroker if they conflict with local [\#2309](https://github.com/pomerium/pomerium/pull/2309) (@wasaga)
- config: add enable\_google\_cloud\_serverless\_authentication to config protobuf [\#2306](https://github.com/pomerium/pomerium/pull/2306) (@calebdoxsey)
- envoy: refactor envoy embedding [\#2296](https://github.com/pomerium/pomerium/pull/2296) (@calebdoxsey)
- envoy: add full version [\#2287](https://github.com/pomerium/pomerium/pull/2287) (@calebdoxsey)
- authorize: handle grpc-web content types like json [\#2268](https://github.com/pomerium/pomerium/pull/2268) (@calebdoxsey)
- xds: retry storing configuration events [\#2266](https://github.com/pomerium/pomerium/pull/2266) (@calebdoxsey)
- envoyconfig: use zipkin tracer [\#2265](https://github.com/pomerium/pomerium/pull/2265) (@calebdoxsey)
- authorize: preserve original context [\#2247](https://github.com/pomerium/pomerium/pull/2247) (@wasaga)
- ppl: add data type, implement string and list matchers [\#2228](https://github.com/pomerium/pomerium/pull/2228) (@calebdoxsey)
- ppl: refactor authorize to evaluate PPL [\#2224](https://github.com/pomerium/pomerium/pull/2224) (@calebdoxsey)
- ppl: convert config policy to ppl [\#2218](https://github.com/pomerium/pomerium/pull/2218) (@calebdoxsey)
- Pomerium Policy Language [\#2202](https://github.com/pomerium/pomerium/pull/2202) (@calebdoxsey)
- telemetry: add hostname tag to metrics [\#2191](https://github.com/pomerium/pomerium/pull/2191) (@wasaga)
- envoy: disable timeouts for kubernetes [\#2189](https://github.com/pomerium/pomerium/pull/2189) (@calebdoxsey)
- registry: implement redis backend [\#2179](https://github.com/pomerium/pomerium/pull/2179) (@calebdoxsey)
- report instance hostname in xds events [\#2175](https://github.com/pomerium/pomerium/pull/2175) (@wasaga)
- databroker: implement leases [\#2172](https://github.com/pomerium/pomerium/pull/2172) (@calebdoxsey)

## Fixed

- config: remove grpc server max connection age options [\#2427](https://github.com/pomerium/pomerium/pull/2427) (@calebdoxsey)
- authorize: add sid to JWT claims [\#2420](https://github.com/pomerium/pomerium/pull/2420) (@calebdoxsey)
- disable http/2 for websockets [\#2399](https://github.com/pomerium/pomerium/pull/2399) (@calebdoxsey)
- ci: update gcloud action [\#2393](https://github.com/pomerium/pomerium/pull/2393) (@travisgroth)
- google: remove WithHTTPClient [\#2391](https://github.com/pomerium/pomerium/pull/2391) (@calebdoxsey)
- telemetry: support b3 headers on gRPC server calls [\#2376](https://github.com/pomerium/pomerium/pull/2376) (@calebdoxsey)
- authorize: allow redirects on deny [\#2361](https://github.com/pomerium/pomerium/pull/2361) (@calebdoxsey)
- authorize: decode CheckRequest path for redirect [\#2357](https://github.com/pomerium/pomerium/pull/2357) (@calebdoxsey)
- envoyconfig: only delete cached files, ignore noisy error [\#2356](https://github.com/pomerium/pomerium/pull/2356) (@calebdoxsey)
- envoy: only check for pid with monitor [\#2355](https://github.com/pomerium/pomerium/pull/2355) (@calebdoxsey)
- fix: timeout in protobuf [\#2341](https://github.com/pomerium/pomerium/pull/2341) (@wasaga)
- authorize: support boolean deny results [\#2338](https://github.com/pomerium/pomerium/pull/2338) (@calebdoxsey)
- ppl: fix not/nor rules [\#2313](https://github.com/pomerium/pomerium/pull/2313) (@calebdoxsey)
- directory/azure: add paging support to user group members call [\#2311](https://github.com/pomerium/pomerium/pull/2311) (@calebdoxsey)
- ocsp: reload on response changes [\#2286](https://github.com/pomerium/pomerium/pull/2286) (@wasaga)
- envoy: fix usage of codec\_type with alpn [\#2277](https://github.com/pomerium/pomerium/pull/2277) (@calebdoxsey)
- databroker: only tag contexts used for UpdateRecords [\#2269](https://github.com/pomerium/pomerium/pull/2269) (@wasaga)
- redis: enforce capacity via ZREVRANGE to avoid race [\#2267](https://github.com/pomerium/pomerium/pull/2267) (@calebdoxsey)
- authorize: only redirect for HTML pages [\#2264](https://github.com/pomerium/pomerium/pull/2264) (@calebdoxsey)
- tracing: support dynamic reloading, more aggressive envoy restart [\#2262](https://github.com/pomerium/pomerium/pull/2262) (@calebdoxsey)
- envoy: always set jwt claim headers even if no value is available [\#2261](https://github.com/pomerium/pomerium/pull/2261) (@calebdoxsey)
- envoy: disable hot-reload for macos [\#2259](https://github.com/pomerium/pomerium/pull/2259) (@calebdoxsey)
- authorize: round timestamp [\#2258](https://github.com/pomerium/pomerium/pull/2258) (@wasaga)
- options: s/shared-key/shared secret [\#2257](https://github.com/pomerium/pomerium/pull/2257) (@desimone)
- config: warn about unrecognized keys  [\#2256](https://github.com/pomerium/pomerium/pull/2256) (@wasaga)
- darwin: use gopsutil v3 to fix arm issue [\#2245](https://github.com/pomerium/pomerium/pull/2245) (@calebdoxsey)
- policy: fix allowed idp claims PPL generation [\#2243](https://github.com/pomerium/pomerium/pull/2243) (@calebdoxsey)
- envoy: exit if envoy exits [\#2240](https://github.com/pomerium/pomerium/pull/2240) (@calebdoxsey)
- envoyconfig: fallback to global custom ca when no policy ca is defined [\#2235](https://github.com/pomerium/pomerium/pull/2235) (@calebdoxsey)
- envoy: add global response headers to local replies [\#2217](https://github.com/pomerium/pomerium/pull/2217) (@calebdoxsey)
- forward auth: don't strip query parameters [\#2216](https://github.com/pomerium/pomerium/pull/2216) (@wasaga)
- PPL: bubble up values, bug fixes [\#2213](https://github.com/pomerium/pomerium/pull/2213) (@calebdoxsey)
- Revert "authenticate,proxy: add same site lax to cookies" [\#2203](https://github.com/pomerium/pomerium/pull/2203) (@desimone)
- authorize: grpc health check [\#2200](https://github.com/pomerium/pomerium/pull/2200) (@wasaga)
- proxy / controplane: use old upstream cipher suite [\#2196](https://github.com/pomerium/pomerium/pull/2196) (@desimone)
- deployment: fix empty version on master builds [\#2193](https://github.com/pomerium/pomerium/pull/2193) (@travisgroth)

## Security

- envoy: only allow embedding [\#2368](https://github.com/pomerium/pomerium/pull/2368) (@calebdoxsey)
- deps: bump envoy to v1.17.3 [\#2198](https://github.com/pomerium/pomerium/pull/2198) (@travisgroth)

## Documentation

- doc updates [\#2433](https://github.com/pomerium/pomerium/pull/2433) (@calebdoxsey)
- Update Console installs to match signing\_key [\#2432](https://github.com/pomerium/pomerium/pull/2432) (@alexfornuto)
- docs/reference: Clarify use of idp\_service\_account [\#2431](https://github.com/pomerium/pomerium/pull/2431) (@the-maldridge)
- docs: clarify device identity, not state via client certs [\#2428](https://github.com/pomerium/pomerium/pull/2428) (@desimone)
- v0.15 release notes [\#2409](https://github.com/pomerium/pomerium/pull/2409) (@travisgroth)
- docs: only secure schemes are supported [\#2408](https://github.com/pomerium/pomerium/pull/2408) (@desimone)
- Installation Docs Restructuring [\#2406](https://github.com/pomerium/pomerium/pull/2406) (@alexfornuto)
- symlink security policy to root of project [\#2396](https://github.com/pomerium/pomerium/pull/2396) (@desimone)
- Enterprise Docs [\#2390](https://github.com/pomerium/pomerium/pull/2390) (@alexfornuto)
- Helm Quickstart Update [\#2380](https://github.com/pomerium/pomerium/pull/2380) (@alexfornuto)
- Docs bug fixes [\#2362](https://github.com/pomerium/pomerium/pull/2362) (@alexfornuto)
- Docs sorting [\#2346](https://github.com/pomerium/pomerium/pull/2346) (@alexfornuto)
- Update installation source for mkcert [\#2340](https://github.com/pomerium/pomerium/pull/2340) (@alexfornuto)
- Update kubernetes-dashboard.md [\#2285](https://github.com/pomerium/pomerium/pull/2285) (@WeeHong)
- Transmission BitTorrent Client Guide [\#2281](https://github.com/pomerium/pomerium/pull/2281) (@alexfornuto)
- docs:  google gcp / workspace instructions [\#2272](https://github.com/pomerium/pomerium/pull/2272) (@desimone)
- docs: update helm values for chart v20.0.0 [\#2242](https://github.com/pomerium/pomerium/pull/2242) (@travisgroth)
- docs: update \_redirects [\#2237](https://github.com/pomerium/pomerium/pull/2237) (@desimone)
- add support for latest version of code-server [\#2229](https://github.com/pomerium/pomerium/pull/2229) (@bpmct)
- fix\(docs\): use correct name for code-server [\#2223](https://github.com/pomerium/pomerium/pull/2223) (@jsjoeio)
- docs: rm broken link [\#2215](https://github.com/pomerium/pomerium/pull/2215) (@alexfornuto)
- docs: Match Tenses [\#2214](https://github.com/pomerium/pomerium/pull/2214) (@alexfornuto)
- Update programmatic-access.md [\#2190](https://github.com/pomerium/pomerium/pull/2190) (@yyolk)
- docs: add v0.14 feature highlights [\#2184](https://github.com/pomerium/pomerium/pull/2184) (@github-actions[bot])
- docs: add v0.14 feature highlights [\#2183](https://github.com/pomerium/pomerium/pull/2183) (@travisgroth)
- docs: update slack link to vanity url [\#2177](https://github.com/pomerium/pomerium/pull/2177) (@travisgroth)

## Dependency

- chore\(deps\): bump gopkg.in/auth0.v5 from 5.19.1 to 5.19.2 [\#2422](https://github.com/pomerium/pomerium/pull/2422) (@dependabot[bot])
- chore\(deps\): bump github.com/go-jose/go-jose/v3 from 3.0.0-rc.1 to 3.0.0 [\#2421](https://github.com/pomerium/pomerium/pull/2421) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/common from 0.29.0 to 0.30.0 [\#2417](https://github.com/pomerium/pomerium/pull/2417) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.30.2 to 0.31.0 [\#2416](https://github.com/pomerium/pomerium/pull/2416) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.51.0 to 0.52.0 [\#2415](https://github.com/pomerium/pomerium/pull/2415) (@dependabot[bot])
- chore\(deps\): bump github.com/shirou/gopsutil/v3 from 3.21.6 to 3.21.7 [\#2414](https://github.com/pomerium/pomerium/pull/2414) (@dependabot[bot])
- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.11.0 to 8.11.1 [\#2413](https://github.com/pomerium/pomerium/pull/2413) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/procfs from 0.7.0 to 0.7.1 [\#2395](https://github.com/pomerium/pomerium/pull/2395) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.50.0 to 0.51.0 [\#2394](https://github.com/pomerium/pomerium/pull/2394) (@dependabot[bot])
- chore\(deps\): bump github.com/google/uuid from 1.2.0 to 1.3.0 [\#2374](https://github.com/pomerium/pomerium/pull/2374) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.30.1 to 0.30.2 [\#2373](https://github.com/pomerium/pomerium/pull/2373) (@dependabot[bot])
- ci: convert to FOSSA scan [\#2371](https://github.com/pomerium/pomerium/pull/2371) (@travisgroth)
- chore\(deps\): bump github.com/golangci/golangci-lint from 1.40.1 to 1.41.1 [\#2353](https://github.com/pomerium/pomerium/pull/2353) (@dependabot[bot])
- chore\(deps\): bump github.com/caddyserver/certmagic from 0.14.0 to 0.14.1 [\#2352](https://github.com/pomerium/pomerium/pull/2352) (@dependabot[bot])
- chore\(deps\): bump github.com/rs/cors from 1.7.0 to 1.8.0 [\#2334](https://github.com/pomerium/pomerium/pull/2334) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.49.0 to 0.50.0 [\#2333](https://github.com/pomerium/pomerium/pull/2333) (@dependabot[bot])
- chore\(deps\): upgrade kind action to v1.2.0 [\#2331](https://github.com/pomerium/pomerium/pull/2331) (@travisgroth)
- chore\(deps\): bump github.com/spf13/cobra from 1.1.3 to 1.2.1 [\#2330](https://github.com/pomerium/pomerium/pull/2330) (@dependabot[bot])
- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.10.0 to 8.11.0 [\#2329](https://github.com/pomerium/pomerium/pull/2329) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/procfs from 0.6.0 to 0.7.0 [\#2328](https://github.com/pomerium/pomerium/pull/2328) (@dependabot[bot])
- chore\(deps\): bump github.com/shirou/gopsutil/v3 from 3.21.5 to 3.21.6 [\#2326](https://github.com/pomerium/pomerium/pull/2326) (@dependabot[bot])
- chore\(deps\): bump go.uber.org/zap from 1.17.0 to 1.18.1 [\#2325](https://github.com/pomerium/pomerium/pull/2325) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/grpc from 1.38.0 to 1.39.0 [\#2324](https://github.com/pomerium/pomerium/pull/2324) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.29.4 to 0.30.1 [\#2323](https://github.com/pomerium/pomerium/pull/2323) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/protobuf from 1.26.0 to 1.27.0 [\#2318](https://github.com/pomerium/pomerium/pull/2318) (@dependabot[bot])
- chore\(deps\): bump github.com/spf13/viper from 1.8.0 to 1.8.1 [\#2317](https://github.com/pomerium/pomerium/pull/2317) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.48.0 to 0.49.0 [\#2315](https://github.com/pomerium/pomerium/pull/2315) (@dependabot[bot])
- chore\(deps\): bump github.com/spf13/viper from 1.7.1 to 1.8.0 [\#2305](https://github.com/pomerium/pomerium/pull/2305) (@dependabot[bot])
- chore\(deps\): bump gopkg.in/auth0.v5 from 5.18.0 to 5.19.1 [\#2304](https://github.com/pomerium/pomerium/pull/2304) (@dependabot[bot])
- chore\(deps\): bump github.com/ory/dockertest/v3 from 3.6.5 to 3.7.0 [\#2303](https://github.com/pomerium/pomerium/pull/2303) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.47.0 to 0.48.0 [\#2295](https://github.com/pomerium/pomerium/pull/2295) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/client\_golang from 1.10.0 to 1.11.0 [\#2294](https://github.com/pomerium/pomerium/pull/2294) (@dependabot[bot])
- chore\(deps\): bump github.com/rs/zerolog from 1.22.0 to 1.23.0 [\#2293](https://github.com/pomerium/pomerium/pull/2293) (@dependabot[bot])
- chore\(deps\): bump gopkg.in/auth0.v5 from 5.17.0 to 5.18.0 [\#2292](https://github.com/pomerium/pomerium/pull/2292) (@dependabot[bot])
- chore\(deps\): bump github.com/caddyserver/certmagic from 0.13.1 to 0.14.0 [\#2291](https://github.com/pomerium/pomerium/pull/2291) (@dependabot[bot])
- chore\(deps\): bump github.com/golang/mock from 1.5.0 to 1.6.0 [\#2290](https://github.com/pomerium/pomerium/pull/2290) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/common from 0.25.0 to 0.29.0 [\#2289](https://github.com/pomerium/pomerium/pull/2289) (@dependabot[bot])
- deps: upgrade to go-jose v3 [\#2284](https://github.com/pomerium/pomerium/pull/2284) (@calebdoxsey)
- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.9.0 to 8.10.0 [\#2276](https://github.com/pomerium/pomerium/pull/2276) (@dependabot[bot])
- chore\(deps\): bump github.com/shirou/gopsutil/v3 from 3.21.4 to 3.21.5 [\#2274](https://github.com/pomerium/pomerium/pull/2274) (@dependabot[bot])
- chore\(deps\): bump gopkg.in/square/go-jose.v2 from 2.5.1 to 2.6.0 [\#2273](https://github.com/pomerium/pomerium/pull/2273) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.28.0 to 0.29.4 [\#2255](https://github.com/pomerium/pomerium/pull/2255) (@dependabot[bot])
- chore\(deps\): bump go.uber.org/zap from 1.16.0 to 1.17.0 [\#2254](https://github.com/pomerium/pomerium/pull/2254) (@dependabot[bot])
- chore\(deps\): bump github.com/google/go-cmp from 0.5.5 to 0.5.6 [\#2253](https://github.com/pomerium/pomerium/pull/2253) (@dependabot[bot])
- chore\(deps\): bump github.com/cenkalti/backoff/v4 from 4.1.0 to 4.1.1 [\#2252](https://github.com/pomerium/pomerium/pull/2252) (@dependabot[bot])
- chore\(deps\): bump github.com/mitchellh/hashstructure/v2 from 2.0.1 to 2.0.2 [\#2251](https://github.com/pomerium/pomerium/pull/2251) (@dependabot[bot])
- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.8.3 to 8.9.0 [\#2249](https://github.com/pomerium/pomerium/pull/2249) (@dependabot[bot])
- darwin: use x86 envoy build for arm64 [\#2246](https://github.com/pomerium/pomerium/pull/2246) (@calebdoxsey)
- chore\(deps\): bump github.com/prometheus/common from 0.24.0 to 0.25.0 [\#2234](https://github.com/pomerium/pomerium/pull/2234) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.46.0 to 0.47.0 [\#2233](https://github.com/pomerium/pomerium/pull/2233) (@dependabot[bot])
- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.8.2 to 8.8.3 [\#2232](https://github.com/pomerium/pomerium/pull/2232) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/grpc from 1.37.1 to 1.38.0 [\#2231](https://github.com/pomerium/pomerium/pull/2231) (@dependabot[bot])
- dependency: update /x/net [\#2227](https://github.com/pomerium/pomerium/pull/2227) (@desimone)
- chore\(deps\): bump github.com/lithammer/shortuuid/v3 from 3.0.6 to 3.0.7 [\#2211](https://github.com/pomerium/pomerium/pull/2211) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/common from 0.23.0 to 0.24.0 [\#2210](https://github.com/pomerium/pomerium/pull/2210) (@dependabot[bot])
- chore\(deps\): bump github.com/rs/zerolog from 1.21.0 to 1.22.0 [\#2209](https://github.com/pomerium/pomerium/pull/2209) (@dependabot[bot])
- chore\(deps\): bump gopkg.in/auth0.v5 from 5.16.0 to 5.17.0 [\#2208](https://github.com/pomerium/pomerium/pull/2208) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/grpc from 1.37.0 to 1.37.1 [\#2207](https://github.com/pomerium/pomerium/pull/2207) (@dependabot[bot])
- chore\(deps\): bump github.com/caddyserver/certmagic from 0.13.0 to 0.13.1 [\#2188](https://github.com/pomerium/pomerium/pull/2188) (@dependabot[bot])
- chore\(deps\): bump gopkg.in/auth0.v5 from 5.15.0 to 5.16.0 [\#2187](https://github.com/pomerium/pomerium/pull/2187) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.45.0 to 0.46.0 [\#2186](https://github.com/pomerium/pomerium/pull/2186) (@dependabot[bot])

## Changed

- redis: increase timeout on test [\#2425](https://github.com/pomerium/pomerium/pull/2425) (@calebdoxsey)
- build: add envoy files to `make clean` [\#2411](https://github.com/pomerium/pomerium/pull/2411) (@travisgroth)
- envoy: bump to 1.19 [\#2392](https://github.com/pomerium/pomerium/pull/2392) (@travisgroth)
- ci: use github app for backport credentials [\#2369](https://github.com/pomerium/pomerium/pull/2369) (@travisgroth)
- databroker: tests [\#2367](https://github.com/pomerium/pomerium/pull/2367) (@calebdoxsey)
- storage/inmemory: add tests for close behavior [\#2336](https://github.com/pomerium/pomerium/pull/2336) (@calebdoxsey)
- redis: refactor change signal test to be more deterministic [\#2335](https://github.com/pomerium/pomerium/pull/2335) (@calebdoxsey)
- internal/envoy: add debugging information if envoy is no longer running [\#2320](https://github.com/pomerium/pomerium/pull/2320) (@travisgroth)
- ci: add coveralls [\#2279](https://github.com/pomerium/pomerium/pull/2279) (@travisgroth)

## [v0.14.7](https://github.com/pomerium/pomerium/tree/v0.14.7) (2021-06-24)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.14.6...v0.14.7)

## Fixed

- directory/azure: add paging support to user group members call [\#2312](https://github.com/pomerium/pomerium/pull/2312) (@github-actions[bot])

## [v0.14.6](https://github.com/pomerium/pomerium/tree/v0.14.6) (2021-06-16)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.14.5...v0.14.6)

## Fixed

- authorize: only redirect for HTML pages \(\#2264\) [\#2298](https://github.com/pomerium/pomerium/pull/2298) (@calebdoxsey)

## [v0.14.5](https://github.com/pomerium/pomerium/tree/v0.14.5) (2021-06-07)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.14.4...v0.14.5)

## Fixed

- envoy: fix usage of codec\_type with alpn [\#2278](https://github.com/pomerium/pomerium/pull/2278) (@github-actions[bot])
- authorize: round JWT claim timestamps [\#2260](https://github.com/pomerium/pomerium/pull/2260) (@wasaga)

## Documentation

- docs: update helm values for chart v20.0.0 [\#2244](https://github.com/pomerium/pomerium/pull/2244) (@github-actions[bot])
- docs: update \_redirects [\#2238](https://github.com/pomerium/pomerium/pull/2238) (@github-actions[bot])

## [v0.14.4](https://github.com/pomerium/pomerium/tree/v0.14.4) (2021-05-24)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.14.3...v0.14.4)

## Fixed

- authorize: add rego functions to custom evaluator [\#2236](https://github.com/pomerium/pomerium/pull/2236) (@calebdoxsey)

## [v0.14.3](https://github.com/pomerium/pomerium/tree/v0.14.3) (2021-05-21)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.14.2...v0.14.3)

## Fixed

- authorize: fix custom rego panic [\#2226](https://github.com/pomerium/pomerium/pull/2226) (@calebdoxsey)

## Changed

- envoy: add global response headers to local replies [\#2225](https://github.com/pomerium/pomerium/pull/2225) (@github-actions[bot])

## [v0.14.2](https://github.com/pomerium/pomerium/tree/v0.14.2) (2021-05-17)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.14.1...v0.14.2)

## Fixed

- Revert "authenticate,proxy: add same site lax to cookies" [\#2204](https://github.com/pomerium/pomerium/pull/2204) (@github-actions[bot])

## Documentation

- Update programmatic-access.md [\#2205](https://github.com/pomerium/pomerium/pull/2205) (@github-actions[bot])

## [v0.14.1](https://github.com/pomerium/pomerium/tree/v0.14.1) (2021-05-13)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.14.0...v0.14.1)

## Fixed

- proxy / controplane: use old upstream cipher suite [\#2197](https://github.com/pomerium/pomerium/pull/2197) (@github-actions[bot])

## Security

- deps: bump envoy to v1.17.3 [\#2199](https://github.com/pomerium/pomerium/pull/2199) (@github-actions[bot])

## Documentation

- docs: update slack link to vanity url [\#2178](https://github.com/pomerium/pomerium/pull/2178) (@github-actions[bot])

## [v0.14.0](https://github.com/pomerium/pomerium/tree/v0.14.0) (2021-05-04)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.14.0-rc2...v0.14.0)

## New

- databroker: store issued at timestamp with session [\#2173](https://github.com/pomerium/pomerium/pull/2173) (@calebdoxsey)
- config: add support for set\_response\_headers in a policy [\#2171](https://github.com/pomerium/pomerium/pull/2171) (@calebdoxsey)
- authenticate,proxy: add same site lax to cookies [\#2159](https://github.com/pomerium/pomerium/pull/2159) (@calebdoxsey)
- xds extended event [\#2158](https://github.com/pomerium/pomerium/pull/2158) (@wasaga)
- config: add client\_crl [\#2157](https://github.com/pomerium/pomerium/pull/2157) (@calebdoxsey)
- config: add support for codec\_type [\#2156](https://github.com/pomerium/pomerium/pull/2156) (@calebdoxsey)
- controlplane: save configuration events to databroker [\#2153](https://github.com/pomerium/pomerium/pull/2153) (@calebdoxsey)
- control plane: add request id to all error pages [\#2149](https://github.com/pomerium/pomerium/pull/2149) (@desimone)
- let pass custom dial opts [\#2144](https://github.com/pomerium/pomerium/pull/2144) (@wasaga)
- envoy: re-implement recommended defaults [\#2123](https://github.com/pomerium/pomerium/pull/2123) (@calebdoxsey)
- Drop tun.cfg.dstHost from jwtCacheKey [\#2115](https://github.com/pomerium/pomerium/pull/2115) (@bl0m1)
- config: remove validate side effects [\#2109](https://github.com/pomerium/pomerium/pull/2109) (@calebdoxsey)
- log context [\#2107](https://github.com/pomerium/pomerium/pull/2107) (@wasaga)
- databroker: add options for maximum capacity [\#2095](https://github.com/pomerium/pomerium/pull/2095) (@calebdoxsey)
- envoyconfig: move most bootstrap config to shared package [\#2088](https://github.com/pomerium/pomerium/pull/2088) (@calebdoxsey)
- envoy: refactor controlplane xds to new envoyconfig package [\#2086](https://github.com/pomerium/pomerium/pull/2086) (@calebdoxsey)
- config: rename headers to set\_response\_headers [\#2081](https://github.com/pomerium/pomerium/pull/2081) (@calebdoxsey)
- crypto: use actual bytes of shared secret, not the base64 encoded representation [\#2075](https://github.com/pomerium/pomerium/pull/2075) (@calebdoxsey)
- cryptutil: use bytes for hmac [\#2067](https://github.com/pomerium/pomerium/pull/2067) (@calebdoxsey)
- cryptutil: always use kek public id, add x509 support [\#2066](https://github.com/pomerium/pomerium/pull/2066) (@calebdoxsey)
- authorize: additional tracing, add benchmark for encryptor [\#2059](https://github.com/pomerium/pomerium/pull/2059) (@calebdoxsey)
- authorize: audit logging [\#2050](https://github.com/pomerium/pomerium/pull/2050) (@calebdoxsey)
- support host:port in metrics\_address [\#2042](https://github.com/pomerium/pomerium/pull/2042) (@wasaga)
- databroker: return server version in Get [\#2039](https://github.com/pomerium/pomerium/pull/2039) (@wasaga)
- authorize: add databroker server and record version to result, force sync via polling [\#2024](https://github.com/pomerium/pomerium/pull/2024) (@calebdoxsey)
- protoutil: add generic transformer [\#2023](https://github.com/pomerium/pomerium/pull/2023) (@calebdoxsey)
- cryptutil: add envelope encryption w/key encryption key and data encryption key [\#2020](https://github.com/pomerium/pomerium/pull/2020) (@calebdoxsey)
- autocert: add metrics for renewal count, total and next expiration [\#2019](https://github.com/pomerium/pomerium/pull/2019) (@calebdoxsey)
- telemetry: add installation id [\#2017](https://github.com/pomerium/pomerium/pull/2017) (@calebdoxsey)
- config: use getters for certificates [\#2001](https://github.com/pomerium/pomerium/pull/2001) (@calebdoxsey)
- config: use getters for authenticate, signout and forward auth urls [\#2000](https://github.com/pomerium/pomerium/pull/2000) (@calebdoxsey)
- xds: use ALPN Auto config for upstream protocol when possible [\#1995](https://github.com/pomerium/pomerium/pull/1995) (@calebdoxsey)
- envoy: upgrade to v1.17.1 [\#1993](https://github.com/pomerium/pomerium/pull/1993) (@calebdoxsey)
- redis: add redis cluster support [\#1992](https://github.com/pomerium/pomerium/pull/1992) (@calebdoxsey)
- redis: add support for redis-sentinel [\#1991](https://github.com/pomerium/pomerium/pull/1991) (@calebdoxsey)
- authorize: set JWT to expire after 5 minutes [\#1980](https://github.com/pomerium/pomerium/pull/1980) (@calebdoxsey)
- identity: infer email from mail claim [\#1977](https://github.com/pomerium/pomerium/pull/1977) (@calebdoxsey)
- ping: identity and directory providers [\#1975](https://github.com/pomerium/pomerium/pull/1975) (@calebdoxsey)
- config: add rewrite\_response\_headers to protobuf [\#1962](https://github.com/pomerium/pomerium/pull/1962) (@calebdoxsey)
- config: add rewrite\_response\_headers option [\#1961](https://github.com/pomerium/pomerium/pull/1961) (@calebdoxsey)
- assets: use embed instead of statik [\#1960](https://github.com/pomerium/pomerium/pull/1960) (@calebdoxsey)
- config: log config source changes [\#1959](https://github.com/pomerium/pomerium/pull/1959) (@calebdoxsey)
- config: multiple endpoints for authorize and databroker [\#1957](https://github.com/pomerium/pomerium/pull/1957) (@calebdoxsey)
- telemetry: add process collector for envoy [\#1948](https://github.com/pomerium/pomerium/pull/1948) (@calebdoxsey)
- use build\_info as liveness gauge metric [\#1940](https://github.com/pomerium/pomerium/pull/1940) (@wasaga)
- metrics: add TLS options [\#1939](https://github.com/pomerium/pomerium/pull/1939) (@calebdoxsey)
- identity: record metric for last refresh [\#1936](https://github.com/pomerium/pomerium/pull/1936) (@calebdoxsey)
- middleware: basic auth equalize lengths of input [\#1934](https://github.com/pomerium/pomerium/pull/1934) (@desimone)
- autocert: remove non-determinism [\#1932](https://github.com/pomerium/pomerium/pull/1932) (@calebdoxsey)
- config: add metrics\_basic\_auth option [\#1917](https://github.com/pomerium/pomerium/pull/1917) (@calebdoxsey)
- envoy: validate binary checksum [\#1908](https://github.com/pomerium/pomerium/pull/1908) (@calebdoxsey)
- config: support map of jwt claim headers [\#1906](https://github.com/pomerium/pomerium/pull/1906) (@calebdoxsey)
- Remove internal/protoutil. [\#1893](https://github.com/pomerium/pomerium/pull/1893) (@yegle)
- databroker: refactor databroker to sync all changes [\#1879](https://github.com/pomerium/pomerium/pull/1879) (@calebdoxsey)
- config: add CertificateFiles to FileWatcherSource list [\#1878](https://github.com/pomerium/pomerium/pull/1878) (@travisgroth)
- config: allow customization of envoy boostrap admin options [\#1872](https://github.com/pomerium/pomerium/pull/1872) (@calebdoxsey)
- proxy: implement pass-through for authenticate backend [\#1870](https://github.com/pomerium/pomerium/pull/1870) (@calebdoxsey)
- authorize: move headers and jwt signing to rego [\#1856](https://github.com/pomerium/pomerium/pull/1856) (@calebdoxsey)

## Fixed

- deployment: update alpine debug image dependencies [\#2154](https://github.com/pomerium/pomerium/pull/2154) (@travisgroth)
- authorize: refactor store locking [\#2151](https://github.com/pomerium/pomerium/pull/2151) (@calebdoxsey)
- databroker: store server version in backend [\#2142](https://github.com/pomerium/pomerium/pull/2142) (@calebdoxsey)
- authorize: audit log had duplicate "message" key [\#2141](https://github.com/pomerium/pomerium/pull/2141) (@desimone)
- httputil: fix SPDY support with reverse proxy [\#2134](https://github.com/pomerium/pomerium/pull/2134) (@calebdoxsey)
- envoyconfig: fix metrics ingress listener name [\#2124](https://github.com/pomerium/pomerium/pull/2124) (@calebdoxsey)
- authorize: fix empty sub policy arrays [\#2119](https://github.com/pomerium/pomerium/pull/2119) (@calebdoxsey)
- authorize: fix unsigned URL [\#2118](https://github.com/pomerium/pomerium/pull/2118) (@calebdoxsey)
- authorize: support arbitrary jwt claims [\#2102](https://github.com/pomerium/pomerium/pull/2102) (@calebdoxsey)
- authorize: support arbitrary jwt claims [\#2106](https://github.com/pomerium/pomerium/pull/2106) (@github-actions[bot])
- xdsmgr: update resource versions on NACK [\#2093](https://github.com/pomerium/pomerium/pull/2093) (@calebdoxsey)
- config: don't change address value on databroker or authorize [\#2092](https://github.com/pomerium/pomerium/pull/2092) (@travisgroth)
- metrics\_address should be optional parameter [\#2087](https://github.com/pomerium/pomerium/pull/2087) (@wasaga)
- propagate changes back from encrypted backend [\#2079](https://github.com/pomerium/pomerium/pull/2079) (@wasaga)
- config: use tls\_custom\_ca from policy when available [\#2077](https://github.com/pomerium/pomerium/pull/2077) (@calebdoxsey)
- databroker: remove unused installation id, close streams when backend is closed [\#2062](https://github.com/pomerium/pomerium/pull/2062) (@calebdoxsey)
- authenticate: fix default sign out url [\#2061](https://github.com/pomerium/pomerium/pull/2061) (@calebdoxsey)
- change require\_proxy\_protocol to use\_proxy\_protocol [\#2043](https://github.com/pomerium/pomerium/pull/2043) (@contrun)
- authorize: bypass data in rego for databroker data [\#2041](https://github.com/pomerium/pomerium/pull/2041) (@calebdoxsey)
- proxy: add nil check for fix-misdirected [\#2040](https://github.com/pomerium/pomerium/pull/2040) (@calebdoxsey)
- config: add headers to config proto [\#1996](https://github.com/pomerium/pomerium/pull/1996) (@calebdoxsey)
- Fix process cpu usage metric [\#1979](https://github.com/pomerium/pomerium/pull/1979) (@wasaga)
- cmd/pomerium: exit 0 for normal shutdown [\#1958](https://github.com/pomerium/pomerium/pull/1958) (@travisgroth)
- proxy: redirect to dashboard for logout [\#1944](https://github.com/pomerium/pomerium/pull/1944) (@calebdoxsey)
- config: fix redirect routes from protobuf [\#1930](https://github.com/pomerium/pomerium/pull/1930) (@travisgroth)
- google: fix default provider URL [\#1928](https://github.com/pomerium/pomerium/pull/1928) (@calebdoxsey)
- fix registry test [\#1911](https://github.com/pomerium/pomerium/pull/1911) (@wasaga)
- ci: pin goreleaser version [\#1900](https://github.com/pomerium/pomerium/pull/1900) (@travisgroth)
- onelogin: fix default scopes for v2 [\#1896](https://github.com/pomerium/pomerium/pull/1896) (@calebdoxsey)
- xds: fix misdirected script [\#1895](https://github.com/pomerium/pomerium/pull/1895) (@calebdoxsey)
- authenticate: validate origin of signout [\#1876](https://github.com/pomerium/pomerium/pull/1876) (@desimone)
- redis: fix deletion versioning [\#1871](https://github.com/pomerium/pomerium/pull/1871) (@calebdoxsey)
- options: header only applies to routes and authN [\#1862](https://github.com/pomerium/pomerium/pull/1862) (@desimone)
- controlplane: add global headers to virtualhost [\#1861](https://github.com/pomerium/pomerium/pull/1861) (@desimone)
- unique envoy cluster ids [\#1858](https://github.com/pomerium/pomerium/pull/1858) (@wasaga)

## Security

- ci: remove codecov [\#2161](https://github.com/pomerium/pomerium/pull/2161) (@travisgroth)
- internal/envoy: always extract envoy [\#2160](https://github.com/pomerium/pomerium/pull/2160) (@travisgroth)
- deps: bump envoy to 1.17.2 [\#2113](https://github.com/pomerium/pomerium/pull/2113) (@travisgroth)
- deps: bump envoy to 1.17.2 [\#2114](https://github.com/pomerium/pomerium/pull/2114) (@github-actions[bot])
- proxy: restrict programmatic URLs to localhost [\#2049](https://github.com/pomerium/pomerium/pull/2049) (@travisgroth)
- authenticate: validate signature on /.pomerium, /.pomerium/sign\_in and /.pomerium/sign\_out [\#2048](https://github.com/pomerium/pomerium/pull/2048) (@travisgroth)

## Documentation

- docs: add inline instructions to generate signing-key [\#2164](https://github.com/pomerium/pomerium/pull/2164) (@desimone)
- docs: add info note to set\_response\_headers [\#2162](https://github.com/pomerium/pomerium/pull/2162) (@calebdoxsey)
- docs: mention alternative bearer token header format [\#2155](https://github.com/pomerium/pomerium/pull/2155) (@travisgroth)
- docs: upgrade notes on `allowed\_users` by ID [\#2133](https://github.com/pomerium/pomerium/pull/2133) (@travisgroth)
- docs: add threat model to security page [\#2097](https://github.com/pomerium/pomerium/pull/2097) (@desimone)
- docs: update community slack link [\#2063](https://github.com/pomerium/pomerium/pull/2063) (@travisgroth)
- Update local-oidc.md [\#1994](https://github.com/pomerium/pomerium/pull/1994) (@dharmendrakariya)
- ping: add documentation [\#1976](https://github.com/pomerium/pomerium/pull/1976) (@calebdoxsey)
- docs: add JWT Verification w/Envoy guide [\#1974](https://github.com/pomerium/pomerium/pull/1974) (@calebdoxsey)
- Update data-storage.md [\#1941](https://github.com/pomerium/pomerium/pull/1941) (@TanguyPatte)
- docs: fix query param name [\#1920](https://github.com/pomerium/pomerium/pull/1920) (@calebdoxsey)
- docs: add breaking sa changes in v0.13 [\#1919](https://github.com/pomerium/pomerium/pull/1919) (@desimone)
- docs: add v0.13 to docs site menu [\#1913](https://github.com/pomerium/pomerium/pull/1913) (@travisgroth)
- docs: update changelog for v0.13.0 [\#1909](https://github.com/pomerium/pomerium/pull/1909) (@desimone)
- docs: update security policy [\#1897](https://github.com/pomerium/pomerium/pull/1897) (@desimone)
- docs: misc upgrade notes and changelog [\#1884](https://github.com/pomerium/pomerium/pull/1884) (@travisgroth)
- docs: add load balancing weight documentation [\#1883](https://github.com/pomerium/pomerium/pull/1883) (@travisgroth)
- docs: additional load balancing documentation [\#1875](https://github.com/pomerium/pomerium/pull/1875) (@travisgroth)

## Dependency

- chore\(deps\): bump github.com/ory/dockertest/v3 from 3.6.3 to 3.6.5 [\#2168](https://github.com/pomerium/pomerium/pull/2168) (@dependabot[bot])
- chore\(deps\): bump github.com/prometheus/common from 0.21.0 to 0.23.0 [\#2167](https://github.com/pomerium/pomerium/pull/2167) (@dependabot[bot])
- chore\(deps\): bump github.com/envoyproxy/protoc-gen-validate from 0.6.0 to 0.6.1 [\#2166](https://github.com/pomerium/pomerium/pull/2166) (@dependabot[bot])
- chore\(deps\): bump github.com/open-policy-agent/opa from 0.27.1 to 0.28.0 [\#2165](https://github.com/pomerium/pomerium/pull/2165) (@dependabot[bot])
- use cached envoy [\#2132](https://github.com/pomerium/pomerium/pull/2132) (@wasaga)
- chore\(deps\): bump github.com/prometheus/common from 0.20.0 to 0.21.0 [\#2130](https://github.com/pomerium/pomerium/pull/2130) (@dependabot[bot])
- chore\(deps\): bump github.com/envoyproxy/protoc-gen-validate from 0.5.1 to 0.6.0 [\#2129](https://github.com/pomerium/pomerium/pull/2129) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.44.0 to 0.45.0 [\#2128](https://github.com/pomerium/pomerium/pull/2128) (@dependabot[bot])
- chore\(deps\): bump github.com/caddyserver/certmagic from 0.12.0 to 0.13.0 [\#2074](https://github.com/pomerium/pomerium/pull/2074) (@dependabot[bot])
- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.8.0 to 8.8.2 [\#2099](https://github.com/pomerium/pomerium/pull/2099) (@dependabot[bot])
- chore\(deps\): bump gopkg.in/auth0.v5 from 5.14.1 to 5.15.0 [\#2098](https://github.com/pomerium/pomerium/pull/2098) (@dependabot[bot])
- do not require project be in GOPATH/src [\#2078](https://github.com/pomerium/pomerium/pull/2078) (@wasaga)
- chore\(deps\): bump google.golang.org/api from 0.43.0 to 0.44.0 [\#2073](https://github.com/pomerium/pomerium/pull/2073) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/grpc from 1.36.1 to 1.37.0 [\#2072](https://github.com/pomerium/pomerium/pull/2072) (@dependabot[bot])
- chore\(deps\): bump gopkg.in/auth0.v5 from 5.13.0 to 5.14.1 [\#2071](https://github.com/pomerium/pomerium/pull/2071) (@dependabot[bot])
- deps: switch from renovate to dependabot [\#2069](https://github.com/pomerium/pomerium/pull/2069) (@travisgroth)
- fix\(deps\): update module github.com/golang/protobuf to v1.5.2 [\#2057](https://github.com/pomerium/pomerium/pull/2057) (@renovate[bot])
- fix\(deps\): update module github.com/envoyproxy/protoc-gen-validate to v0.5.1 [\#2056](https://github.com/pomerium/pomerium/pull/2056) (@renovate[bot])
- fix\(deps\): update google.golang.org/genproto commit hash to 6c239bb [\#2054](https://github.com/pomerium/pomerium/pull/2054) (@renovate[bot])
- fix\(deps\): update golang.org/x/oauth2 commit hash to 2e8d934 [\#2053](https://github.com/pomerium/pomerium/pull/2053) (@renovate[bot])
- fix\(deps\): update golang.org/x/net commit hash to 0fccb6f [\#2052](https://github.com/pomerium/pomerium/pull/2052) (@renovate[bot])
- skip REDIS cluster test if GOOS != linux [\#2045](https://github.com/pomerium/pomerium/pull/2045) (@wasaga)
- fix\(deps\): update module gopkg.in/auth0.v5 to v5.13.0 [\#2037](https://github.com/pomerium/pomerium/pull/2037) (@renovate[bot])
- fix\(deps\): update module google.golang.org/grpc to v1.36.1 [\#2036](https://github.com/pomerium/pomerium/pull/2036) (@renovate[bot])
- fix\(deps\): update module google.golang.org/api to v0.43.0 [\#2035](https://github.com/pomerium/pomerium/pull/2035) (@renovate[bot])
- fix\(deps\): update module github.com/rs/zerolog to v1.21.0 [\#2034](https://github.com/pomerium/pomerium/pull/2034) (@renovate[bot])
- fix\(deps\): update module github.com/prometheus/common to v0.20.0 [\#2033](https://github.com/pomerium/pomerium/pull/2033) (@renovate[bot])
- fix\(deps\): update module github.com/go-redis/redis/v8 to v8.8.0 [\#2032](https://github.com/pomerium/pomerium/pull/2032) (@renovate[bot])
- chore\(deps\): update mikefarah/yq action to v4.6.3 [\#2031](https://github.com/pomerium/pomerium/pull/2031) (@renovate[bot])
- fix\(deps\): update google.golang.org/genproto commit hash to 679c6ae [\#2030](https://github.com/pomerium/pomerium/pull/2030) (@renovate[bot])
- fix\(deps\): update golang.org/x/oauth2 commit hash to 22b0ada [\#2029](https://github.com/pomerium/pomerium/pull/2029) (@renovate[bot])
- fix\(deps\): update golang.org/x/net commit hash to 61e0566 [\#2028](https://github.com/pomerium/pomerium/pull/2028) (@renovate[bot])
- fix\(deps\): update golang.org/x/crypto commit hash to 0c34fe9 [\#2027](https://github.com/pomerium/pomerium/pull/2027) (@renovate[bot])
- deps: bundle all patch upgrades in a single group [\#2016](https://github.com/pomerium/pomerium/pull/2016) (@travisgroth)
- fix\(deps\): update module google.golang.org/protobuf to v1.26.0 [\#2012](https://github.com/pomerium/pomerium/pull/2012) (@renovate[bot])
- fix\(deps\): update module github.com/prometheus/client\_golang to v1.10.0 [\#2011](https://github.com/pomerium/pomerium/pull/2011) (@renovate[bot])
- fix\(deps\): update module github.com/google/btree to v1.0.1 [\#2010](https://github.com/pomerium/pomerium/pull/2010) (@renovate[bot])
- fix\(deps\): update module github.com/golang/protobuf to v1.5.1 [\#2009](https://github.com/pomerium/pomerium/pull/2009) (@renovate[bot])
- fix\(deps\): update module github.com/envoyproxy/protoc-gen-validate to v0.5.0 [\#2008](https://github.com/pomerium/pomerium/pull/2008) (@renovate[bot])
- chore\(deps\): update mikefarah/yq action to v4.6.2 [\#2007](https://github.com/pomerium/pomerium/pull/2007) (@renovate[bot])
- fix\(deps\): update google.golang.org/genproto commit hash to 5f0e893 [\#2006](https://github.com/pomerium/pomerium/pull/2006) (@renovate[bot])
- fix\(deps\): update golang.org/x/net commit hash to d523dce [\#2005](https://github.com/pomerium/pomerium/pull/2005) (@renovate[bot])
- fix\(deps\): update module google.golang.org/api to v0.42.0 [\#1989](https://github.com/pomerium/pomerium/pull/1989) (@renovate[bot])
- fix\(deps\): update module github.com/open-policy-agent/opa to v0.27.1 [\#1988](https://github.com/pomerium/pomerium/pull/1988) (@renovate[bot])
- fix\(deps\): update module github.com/hashicorp/go-multierror to v1.1.1 [\#1987](https://github.com/pomerium/pomerium/pull/1987) (@renovate[bot])
- fix\(deps\): update module contrib.go.opencensus.io/exporter/prometheus to v0.3.0 [\#1986](https://github.com/pomerium/pomerium/pull/1986) (@renovate[bot])
- chore\(deps\): update codecov/codecov-action action to v1.3.1 [\#1985](https://github.com/pomerium/pomerium/pull/1985) (@renovate[bot])
- fix\(deps\): update google.golang.org/genproto commit hash to 8812039 [\#1984](https://github.com/pomerium/pomerium/pull/1984) (@renovate[bot])
- fix\(deps\): update golang.org/x/oauth2 commit hash to cd4f82c [\#1983](https://github.com/pomerium/pomerium/pull/1983) (@renovate[bot])
- fix\(deps\): update golang.org/x/crypto commit hash to 513c2a4 [\#1982](https://github.com/pomerium/pomerium/pull/1982) (@renovate[bot])
- fix\(deps\): update module github.com/prometheus/procfs to v0.6.0 [\#1969](https://github.com/pomerium/pomerium/pull/1969) (@renovate[bot])
- fix\(deps\): update module github.com/google/go-cmp to v0.5.5 [\#1968](https://github.com/pomerium/pomerium/pull/1968) (@renovate[bot])
- fix\(deps\): update module github.com/go-redis/redis/v8 to v8.7.1 [\#1967](https://github.com/pomerium/pomerium/pull/1967) (@renovate[bot])
- fix\(deps\): update google.golang.org/genproto commit hash to 9728d6b [\#1966](https://github.com/pomerium/pomerium/pull/1966) (@renovate[bot])
- fix\(deps\): update github.com/nsf/jsondiff commit hash to 6ea3239 [\#1965](https://github.com/pomerium/pomerium/pull/1965) (@renovate[bot])
- fix\(deps\): update module github.com/go-chi/chi to v5 [\#1956](https://github.com/pomerium/pomerium/pull/1956) (@renovate[bot])
- fix\(deps\): update module google.golang.org/grpc to v1.36.0 [\#1955](https://github.com/pomerium/pomerium/pull/1955) (@renovate[bot])
- fix\(deps\): update module go.opencensus.io to v0.23.0 [\#1954](https://github.com/pomerium/pomerium/pull/1954) (@renovate[bot])
- fix\(deps\): update module github.com/lithammer/shortuuid/v3 to v3.0.6 [\#1953](https://github.com/pomerium/pomerium/pull/1953) (@renovate[bot])
- chore\(deps\): update vuepress monorepo to v1.8.2 [\#1952](https://github.com/pomerium/pomerium/pull/1952) (@renovate[bot])
- chore\(deps\): update mikefarah/yq action to v4.6.1 [\#1951](https://github.com/pomerium/pomerium/pull/1951) (@renovate[bot])
- fix\(deps\): update google.golang.org/genproto commit hash to ab064af [\#1950](https://github.com/pomerium/pomerium/pull/1950) (@renovate[bot])
- fix\(deps\): update golang.org/x/net commit hash to e18ecbb [\#1949](https://github.com/pomerium/pomerium/pull/1949) (@renovate[bot])
- chore\(deps\): update yaml v2 to v3 [\#1927](https://github.com/pomerium/pomerium/pull/1927) (@desimone)
- chore\(deps\): update vuepress monorepo to v1.8.1 [\#1891](https://github.com/pomerium/pomerium/pull/1891) (@renovate[bot])
- chore\(deps\): update module spf13/cobra to v1.1.3 [\#1890](https://github.com/pomerium/pomerium/pull/1890) (@renovate[bot])
- chore\(deps\): update module google.golang.org/api to v0.40.0 [\#1889](https://github.com/pomerium/pomerium/pull/1889) (@renovate[bot])
- chore\(deps\): update mikefarah/yq action to v4.5.1 [\#1888](https://github.com/pomerium/pomerium/pull/1888) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to e7f2df4 [\#1887](https://github.com/pomerium/pomerium/pull/1887) (@renovate[bot])
- chore\(deps\): update golang.org/x/oauth2 commit hash to 6667018 [\#1886](https://github.com/pomerium/pomerium/pull/1886) (@renovate[bot])
- chore\(deps\): update module auth0 to v5 [\#1868](https://github.com/pomerium/pomerium/pull/1868) (@renovate[bot])
- chore\(deps\): update module google.golang.org/api to v0.39.0 [\#1867](https://github.com/pomerium/pomerium/pull/1867) (@renovate[bot])
- chore\(deps\): update module go-redis/redis/v8 to v8.5.0 [\#1866](https://github.com/pomerium/pomerium/pull/1866) (@renovate[bot])
- chore\(deps\): update mikefarah/yq action to v4.5.0 [\#1865](https://github.com/pomerium/pomerium/pull/1865) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to bba0dbe [\#1864](https://github.com/pomerium/pomerium/pull/1864) (@renovate[bot])
- chore\(deps\): update golang.org/x/oauth2 commit hash to 0101308 [\#1863](https://github.com/pomerium/pomerium/pull/1863) (@renovate[bot])

## Deployment

- deployment: update get-envoy script and release hooks [\#2111](https://github.com/pomerium/pomerium/pull/2111) (@travisgroth)
- deployment: Publish OS packages to cloudsmith [\#2105](https://github.com/pomerium/pomerium/pull/2105) (@travisgroth)
- deployment: update get-envoy script and release hooks [\#2112](https://github.com/pomerium/pomerium/pull/2112) (@github-actions[bot])
- deployment: Publish OS packages to cloudsmith [\#2108](https://github.com/pomerium/pomerium/pull/2108) (@github-actions[bot])
- ci: cache build and test binaries [\#1938](https://github.com/pomerium/pomerium/pull/1938) (@desimone)
- ci: go 1.16.x, cached tests [\#1937](https://github.com/pomerium/pomerium/pull/1937) (@desimone)

## Changed

- authorize: remove log [\#2122](https://github.com/pomerium/pomerium/pull/2122) (@calebdoxsey)
- config related metrics [\#2065](https://github.com/pomerium/pomerium/pull/2065) (@wasaga)
- proxy: support re-proxying request through control plane for kubernetes [\#2051](https://github.com/pomerium/pomerium/pull/2051) (@calebdoxsey)
- add default gitlab url [\#2044](https://github.com/pomerium/pomerium/pull/2044) (@contrun)
- Updating Doc for Pomerium-Dex Exercise [\#2018](https://github.com/pomerium/pomerium/pull/2018) (@dharmendrakariya)
- Add `xff\_num\_trusted\_hops` config option [\#2003](https://github.com/pomerium/pomerium/pull/2003) (@ntoofu)
- envoy: restrict permissions on embedded envoy binary [\#1999](https://github.com/pomerium/pomerium/pull/1999) (@calebdoxsey)
- ci: deploy master to integration environments [\#1973](https://github.com/pomerium/pomerium/pull/1973) (@travisgroth)
- oidc: use groups claim from ID token if present [\#1970](https://github.com/pomerium/pomerium/pull/1970) (@bonifaido)
- config: expose viper policy hooks [\#1947](https://github.com/pomerium/pomerium/pull/1947) (@calebdoxsey)
- ci: deploy latest release to test environment [\#1916](https://github.com/pomerium/pomerium/pull/1916) (@travisgroth)
- logs: strip query string [\#1894](https://github.com/pomerium/pomerium/pull/1894) (@calebdoxsey)
- in-memory service registry [\#1892](https://github.com/pomerium/pomerium/pull/1892) (@wasaga)
- controlplane: maybe fix flaky test [\#1873](https://github.com/pomerium/pomerium/pull/1873) (@calebdoxsey)
- remove generated code from code coverage metrics [\#1857](https://github.com/pomerium/pomerium/pull/1857) (@travisgroth)

## [v0.14.0-rc2](https://github.com/pomerium/pomerium/tree/v0.14.0-rc2) (2021-04-29)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.14.0-rc1...v0.14.0-rc2)

## New

- controlplane: save configuration events to databroker [\#2153](https://github.com/pomerium/pomerium/pull/2153) (@calebdoxsey)
- control plane: add request id to all error pages [\#2149](https://github.com/pomerium/pomerium/pull/2149) (@desimone)
- let pass custom dial opts [\#2144](https://github.com/pomerium/pomerium/pull/2144) (@wasaga)
- envoy: re-implement recommended defaults [\#2123](https://github.com/pomerium/pomerium/pull/2123) (@calebdoxsey)
- Drop tun.cfg.dstHost from jwtCacheKey [\#2115](https://github.com/pomerium/pomerium/pull/2115) (@bl0m1)
- config: remove validate side effects [\#2109](https://github.com/pomerium/pomerium/pull/2109) (@calebdoxsey)
- log context [\#2107](https://github.com/pomerium/pomerium/pull/2107) (@wasaga)
- databroker: add options for maximum capacity [\#2095](https://github.com/pomerium/pomerium/pull/2095) (@calebdoxsey)

## Fixed

- deployment: update alpine debug image dependencies [\#2154](https://github.com/pomerium/pomerium/pull/2154) (@travisgroth)
- authorize: refactor store locking [\#2151](https://github.com/pomerium/pomerium/pull/2151) (@calebdoxsey)
- databroker: store server version in backend [\#2142](https://github.com/pomerium/pomerium/pull/2142) (@calebdoxsey)
- authorize: audit log had duplicate "message" key [\#2141](https://github.com/pomerium/pomerium/pull/2141) (@desimone)
- httputil: fix SPDY support with reverse proxy [\#2134](https://github.com/pomerium/pomerium/pull/2134) (@calebdoxsey)
- envoyconfig: fix metrics ingress listener name [\#2124](https://github.com/pomerium/pomerium/pull/2124) (@calebdoxsey)
- authorize: fix empty sub policy arrays [\#2119](https://github.com/pomerium/pomerium/pull/2119) (@calebdoxsey)
- authorize: fix unsigned URL [\#2118](https://github.com/pomerium/pomerium/pull/2118) (@calebdoxsey)
- authorize: support arbitrary jwt claims [\#2102](https://github.com/pomerium/pomerium/pull/2102) (@calebdoxsey)

## Security

- deps: bump envoy to 1.17.2 [\#2113](https://github.com/pomerium/pomerium/pull/2113) (@travisgroth)

## Documentation

- docs: mention alternative bearer token header format [\#2155](https://github.com/pomerium/pomerium/pull/2155) (@travisgroth)
- docs: upgrade notes on `allowed\_users` by ID [\#2133](https://github.com/pomerium/pomerium/pull/2133) (@travisgroth)

## Dependency

- use cached envoy [\#2132](https://github.com/pomerium/pomerium/pull/2132) (@wasaga)
- chore\(deps\): bump github.com/prometheus/common from 0.20.0 to 0.21.0 [\#2130](https://github.com/pomerium/pomerium/pull/2130) (@dependabot[bot])
- chore\(deps\): bump github.com/envoyproxy/protoc-gen-validate from 0.5.1 to 0.6.0 [\#2129](https://github.com/pomerium/pomerium/pull/2129) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/api from 0.44.0 to 0.45.0 [\#2128](https://github.com/pomerium/pomerium/pull/2128) (@dependabot[bot])
- chore\(deps\): bump github.com/caddyserver/certmagic from 0.12.0 to 0.13.0 [\#2074](https://github.com/pomerium/pomerium/pull/2074) (@dependabot[bot])

## Deployment

- deployment: update get-envoy script and release hooks [\#2111](https://github.com/pomerium/pomerium/pull/2111) (@travisgroth)
- deployment: Publish OS packages to cloudsmith [\#2105](https://github.com/pomerium/pomerium/pull/2105) (@travisgroth)

## Changed

- authorize: remove log [\#2122](https://github.com/pomerium/pomerium/pull/2122) (@calebdoxsey)

## [v0.14.0-rc1](https://github.com/pomerium/pomerium/tree/v0.14.0-rc1) (2021-04-22)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.13.6...v0.14.0-rc1)

## Breaking

- directory: remove provider from user id [\#2068](https://github.com/pomerium/pomerium/pull/2068) (@calebdoxsey)

## New

- envoyconfig: move most bootstrap config to shared package [\#2088](https://github.com/pomerium/pomerium/pull/2088) (@calebdoxsey)
- envoy: refactor controlplane xds to new envoyconfig package [\#2086](https://github.com/pomerium/pomerium/pull/2086) (@calebdoxsey)
- config: rename headers to set\_response\_headers [\#2081](https://github.com/pomerium/pomerium/pull/2081) (@calebdoxsey)
- crypto: use actual bytes of shared secret, not the base64 encoded representation [\#2075](https://github.com/pomerium/pomerium/pull/2075) (@calebdoxsey)
- cryptutil: use bytes for hmac [\#2067](https://github.com/pomerium/pomerium/pull/2067) (@calebdoxsey)
- cryptutil: always use kek public id, add x509 support [\#2066](https://github.com/pomerium/pomerium/pull/2066) (@calebdoxsey)
- authorize: additional tracing, add benchmark for encryptor [\#2059](https://github.com/pomerium/pomerium/pull/2059) (@calebdoxsey)
- authorize: audit logging [\#2050](https://github.com/pomerium/pomerium/pull/2050) (@calebdoxsey)
- support host:port in metrics\_address [\#2042](https://github.com/pomerium/pomerium/pull/2042) (@wasaga)
- databroker: return server version in Get [\#2039](https://github.com/pomerium/pomerium/pull/2039) (@wasaga)
- authorize: add databroker server and record version to result, force sync via polling [\#2024](https://github.com/pomerium/pomerium/pull/2024) (@calebdoxsey)
- protoutil: add generic transformer [\#2023](https://github.com/pomerium/pomerium/pull/2023) (@calebdoxsey)
- cryptutil: add envelope encryption w/key encryption key and data encryption key [\#2020](https://github.com/pomerium/pomerium/pull/2020) (@calebdoxsey)
- autocert: add metrics for renewal count, total and next expiration [\#2019](https://github.com/pomerium/pomerium/pull/2019) (@calebdoxsey)
- telemetry: add installation id [\#2017](https://github.com/pomerium/pomerium/pull/2017) (@calebdoxsey)
- config: use getters for certificates [\#2001](https://github.com/pomerium/pomerium/pull/2001) (@calebdoxsey)
- config: use getters for authenticate, signout and forward auth urls [\#2000](https://github.com/pomerium/pomerium/pull/2000) (@calebdoxsey)
- xds: use ALPN Auto config for upstream protocol when possible [\#1995](https://github.com/pomerium/pomerium/pull/1995) (@calebdoxsey)
- envoy: upgrade to v1.17.1 [\#1993](https://github.com/pomerium/pomerium/pull/1993) (@calebdoxsey)
- redis: add redis cluster support [\#1992](https://github.com/pomerium/pomerium/pull/1992) (@calebdoxsey)
- redis: add support for redis-sentinel [\#1991](https://github.com/pomerium/pomerium/pull/1991) (@calebdoxsey)
- authorize: set JWT to expire after 5 minutes [\#1980](https://github.com/pomerium/pomerium/pull/1980) (@calebdoxsey)
- identity: infer email from mail claim [\#1977](https://github.com/pomerium/pomerium/pull/1977) (@calebdoxsey)
- ping: identity and directory providers [\#1975](https://github.com/pomerium/pomerium/pull/1975) (@calebdoxsey)
- config: add rewrite\_response\_headers to protobuf [\#1962](https://github.com/pomerium/pomerium/pull/1962) (@calebdoxsey)
- config: add rewrite\_response\_headers option [\#1961](https://github.com/pomerium/pomerium/pull/1961) (@calebdoxsey)
- assets: use embed instead of statik [\#1960](https://github.com/pomerium/pomerium/pull/1960) (@calebdoxsey)
- config: log config source changes [\#1959](https://github.com/pomerium/pomerium/pull/1959) (@calebdoxsey)
- config: multiple endpoints for authorize and databroker [\#1957](https://github.com/pomerium/pomerium/pull/1957) (@calebdoxsey)
- telemetry: add process collector for envoy [\#1948](https://github.com/pomerium/pomerium/pull/1948) (@calebdoxsey)
- use build\_info as liveness gauge metric [\#1940](https://github.com/pomerium/pomerium/pull/1940) (@wasaga)
- metrics: add TLS options [\#1939](https://github.com/pomerium/pomerium/pull/1939) (@calebdoxsey)
- identity: record metric for last refresh [\#1936](https://github.com/pomerium/pomerium/pull/1936) (@calebdoxsey)
- middleware: basic auth equalize lengths of input [\#1934](https://github.com/pomerium/pomerium/pull/1934) (@desimone)
- autocert: remove non-determinism [\#1932](https://github.com/pomerium/pomerium/pull/1932) (@calebdoxsey)
- config: add metrics\_basic\_auth option [\#1917](https://github.com/pomerium/pomerium/pull/1917) (@calebdoxsey)
- envoy: validate binary checksum [\#1908](https://github.com/pomerium/pomerium/pull/1908) (@calebdoxsey)
- config: support map of jwt claim headers [\#1906](https://github.com/pomerium/pomerium/pull/1906) (@calebdoxsey)
- Remove internal/protoutil. [\#1893](https://github.com/pomerium/pomerium/pull/1893) (@yegle)
- databroker: refactor databroker to sync all changes [\#1879](https://github.com/pomerium/pomerium/pull/1879) (@calebdoxsey)
- config: add CertificateFiles to FileWatcherSource list [\#1878](https://github.com/pomerium/pomerium/pull/1878) (@travisgroth)
- config: allow customization of envoy boostrap admin options [\#1872](https://github.com/pomerium/pomerium/pull/1872) (@calebdoxsey)
- proxy: implement pass-through for authenticate backend [\#1870](https://github.com/pomerium/pomerium/pull/1870) (@calebdoxsey)
- authorize: move headers and jwt signing to rego [\#1856](https://github.com/pomerium/pomerium/pull/1856) (@calebdoxsey)

## Fixed

- authorize: support arbitrary jwt claims [\#2106](https://github.com/pomerium/pomerium/pull/2106) (@github-actions[bot])
- xdsmgr: update resource versions on NACK [\#2093](https://github.com/pomerium/pomerium/pull/2093) (@calebdoxsey)
- config: don't change address value on databroker or authorize [\#2092](https://github.com/pomerium/pomerium/pull/2092) (@travisgroth)
- metrics\_address should be optional parameter [\#2087](https://github.com/pomerium/pomerium/pull/2087) (@wasaga)
- propagate changes back from encrypted backend [\#2079](https://github.com/pomerium/pomerium/pull/2079) (@wasaga)
- config: use tls\_custom\_ca from policy when available [\#2077](https://github.com/pomerium/pomerium/pull/2077) (@calebdoxsey)
- databroker: remove unused installation id, close streams when backend is closed [\#2062](https://github.com/pomerium/pomerium/pull/2062) (@calebdoxsey)
- authenticate: fix default sign out url [\#2061](https://github.com/pomerium/pomerium/pull/2061) (@calebdoxsey)
- change require\_proxy\_protocol to use\_proxy\_protocol [\#2043](https://github.com/pomerium/pomerium/pull/2043) (@contrun)
- authorize: bypass data in rego for databroker data [\#2041](https://github.com/pomerium/pomerium/pull/2041) (@calebdoxsey)
- proxy: add nil check for fix-misdirected [\#2040](https://github.com/pomerium/pomerium/pull/2040) (@calebdoxsey)
- config: add headers to config proto [\#1996](https://github.com/pomerium/pomerium/pull/1996) (@calebdoxsey)
- Fix process cpu usage metric [\#1979](https://github.com/pomerium/pomerium/pull/1979) (@wasaga)
- cmd/pomerium: exit 0 for normal shutdown [\#1958](https://github.com/pomerium/pomerium/pull/1958) (@travisgroth)
- proxy: redirect to dashboard for logout [\#1944](https://github.com/pomerium/pomerium/pull/1944) (@calebdoxsey)
- config: fix redirect routes from protobuf [\#1930](https://github.com/pomerium/pomerium/pull/1930) (@travisgroth)
- google: fix default provider URL [\#1928](https://github.com/pomerium/pomerium/pull/1928) (@calebdoxsey)
- fix registry test [\#1911](https://github.com/pomerium/pomerium/pull/1911) (@wasaga)
- ci: pin goreleaser version [\#1900](https://github.com/pomerium/pomerium/pull/1900) (@travisgroth)
- onelogin: fix default scopes for v2 [\#1896](https://github.com/pomerium/pomerium/pull/1896) (@calebdoxsey)
- xds: fix misdirected script [\#1895](https://github.com/pomerium/pomerium/pull/1895) (@calebdoxsey)
- authenticate: validate origin of signout [\#1876](https://github.com/pomerium/pomerium/pull/1876) (@desimone)
- redis: fix deletion versioning [\#1871](https://github.com/pomerium/pomerium/pull/1871) (@calebdoxsey)
- options: header only applies to routes and authN [\#1862](https://github.com/pomerium/pomerium/pull/1862) (@desimone)
- controlplane: add global headers to virtualhost [\#1861](https://github.com/pomerium/pomerium/pull/1861) (@desimone)
- unique envoy cluster ids [\#1858](https://github.com/pomerium/pomerium/pull/1858) (@wasaga)

## Security

- deps: bump envoy to 1.17.2 [\#2114](https://github.com/pomerium/pomerium/pull/2114) (@github-actions[bot])
- proxy: restrict programmatic URLs to localhost [\#2049](https://github.com/pomerium/pomerium/pull/2049) (@travisgroth)
- authenticate: validate signature on /.pomerium, /.pomerium/sign\_in and /.pomerium/sign\_out [\#2048](https://github.com/pomerium/pomerium/pull/2048) (@travisgroth)

## Documentation

- docs: add threat model to security page [\#2097](https://github.com/pomerium/pomerium/pull/2097) (@desimone)
- docs: update community slack link [\#2063](https://github.com/pomerium/pomerium/pull/2063) (@travisgroth)
- Update local-oidc.md [\#1994](https://github.com/pomerium/pomerium/pull/1994) (@dharmendrakariya)
- ping: add documentation [\#1976](https://github.com/pomerium/pomerium/pull/1976) (@calebdoxsey)
- docs: add JWT Verification w/Envoy guide [\#1974](https://github.com/pomerium/pomerium/pull/1974) (@calebdoxsey)
- Update data-storage.md [\#1941](https://github.com/pomerium/pomerium/pull/1941) (@TanguyPatte)
- docs: fix query param name [\#1920](https://github.com/pomerium/pomerium/pull/1920) (@calebdoxsey)
- docs: add breaking sa changes in v0.13 [\#1919](https://github.com/pomerium/pomerium/pull/1919) (@desimone)
- docs: add v0.13 to docs site menu [\#1913](https://github.com/pomerium/pomerium/pull/1913) (@travisgroth)
- docs: update changelog for v0.13.0 [\#1909](https://github.com/pomerium/pomerium/pull/1909) (@desimone)
- docs: update security policy [\#1897](https://github.com/pomerium/pomerium/pull/1897) (@desimone)
- docs: misc upgrade notes and changelog [\#1884](https://github.com/pomerium/pomerium/pull/1884) (@travisgroth)
- docs: add load balancing weight documentation [\#1883](https://github.com/pomerium/pomerium/pull/1883) (@travisgroth)
- docs: additional load balancing documentation [\#1875](https://github.com/pomerium/pomerium/pull/1875) (@travisgroth)

## Dependency

- chore\(deps\): bump github.com/go-redis/redis/v8 from 8.8.0 to 8.8.2 [\#2099](https://github.com/pomerium/pomerium/pull/2099) (@dependabot[bot])
- chore\(deps\): bump gopkg.in/auth0.v5 from 5.14.1 to 5.15.0 [\#2098](https://github.com/pomerium/pomerium/pull/2098) (@dependabot[bot])
- do not require project be in GOPATH/src [\#2078](https://github.com/pomerium/pomerium/pull/2078) (@wasaga)
- chore\(deps\): bump google.golang.org/api from 0.43.0 to 0.44.0 [\#2073](https://github.com/pomerium/pomerium/pull/2073) (@dependabot[bot])
- chore\(deps\): bump google.golang.org/grpc from 1.36.1 to 1.37.0 [\#2072](https://github.com/pomerium/pomerium/pull/2072) (@dependabot[bot])
- chore\(deps\): bump gopkg.in/auth0.v5 from 5.13.0 to 5.14.1 [\#2071](https://github.com/pomerium/pomerium/pull/2071) (@dependabot[bot])
- deps: switch from renovate to dependabot [\#2069](https://github.com/pomerium/pomerium/pull/2069) (@travisgroth)
- fix\(deps\): update module github.com/golang/protobuf to v1.5.2 [\#2057](https://github.com/pomerium/pomerium/pull/2057) (@renovate[bot])
- fix\(deps\): update module github.com/envoyproxy/protoc-gen-validate to v0.5.1 [\#2056](https://github.com/pomerium/pomerium/pull/2056) (@renovate[bot])
- fix\(deps\): update google.golang.org/genproto commit hash to 6c239bb [\#2054](https://github.com/pomerium/pomerium/pull/2054) (@renovate[bot])
- fix\(deps\): update golang.org/x/oauth2 commit hash to 2e8d934 [\#2053](https://github.com/pomerium/pomerium/pull/2053) (@renovate[bot])
- fix\(deps\): update golang.org/x/net commit hash to 0fccb6f [\#2052](https://github.com/pomerium/pomerium/pull/2052) (@renovate[bot])
- skip REDIS cluster test if GOOS != linux [\#2045](https://github.com/pomerium/pomerium/pull/2045) (@wasaga)
- fix\(deps\): update module gopkg.in/auth0.v5 to v5.13.0 [\#2037](https://github.com/pomerium/pomerium/pull/2037) (@renovate[bot])
- fix\(deps\): update module google.golang.org/grpc to v1.36.1 [\#2036](https://github.com/pomerium/pomerium/pull/2036) (@renovate[bot])
- fix\(deps\): update module google.golang.org/api to v0.43.0 [\#2035](https://github.com/pomerium/pomerium/pull/2035) (@renovate[bot])
- fix\(deps\): update module github.com/rs/zerolog to v1.21.0 [\#2034](https://github.com/pomerium/pomerium/pull/2034) (@renovate[bot])
- fix\(deps\): update module github.com/prometheus/common to v0.20.0 [\#2033](https://github.com/pomerium/pomerium/pull/2033) (@renovate[bot])
- fix\(deps\): update module github.com/go-redis/redis/v8 to v8.8.0 [\#2032](https://github.com/pomerium/pomerium/pull/2032) (@renovate[bot])
- chore\(deps\): update mikefarah/yq action to v4.6.3 [\#2031](https://github.com/pomerium/pomerium/pull/2031) (@renovate[bot])
- fix\(deps\): update google.golang.org/genproto commit hash to 679c6ae [\#2030](https://github.com/pomerium/pomerium/pull/2030) (@renovate[bot])
- fix\(deps\): update golang.org/x/oauth2 commit hash to 22b0ada [\#2029](https://github.com/pomerium/pomerium/pull/2029) (@renovate[bot])
- fix\(deps\): update golang.org/x/net commit hash to 61e0566 [\#2028](https://github.com/pomerium/pomerium/pull/2028) (@renovate[bot])
- fix\(deps\): update golang.org/x/crypto commit hash to 0c34fe9 [\#2027](https://github.com/pomerium/pomerium/pull/2027) (@renovate[bot])
- deps: bundle all patch upgrades in a single group [\#2016](https://github.com/pomerium/pomerium/pull/2016) (@travisgroth)
- fix\(deps\): update module google.golang.org/protobuf to v1.26.0 [\#2012](https://github.com/pomerium/pomerium/pull/2012) (@renovate[bot])
- fix\(deps\): update module github.com/prometheus/client\_golang to v1.10.0 [\#2011](https://github.com/pomerium/pomerium/pull/2011) (@renovate[bot])
- fix\(deps\): update module github.com/google/btree to v1.0.1 [\#2010](https://github.com/pomerium/pomerium/pull/2010) (@renovate[bot])
- fix\(deps\): update module github.com/golang/protobuf to v1.5.1 [\#2009](https://github.com/pomerium/pomerium/pull/2009) (@renovate[bot])
- fix\(deps\): update module github.com/envoyproxy/protoc-gen-validate to v0.5.0 [\#2008](https://github.com/pomerium/pomerium/pull/2008) (@renovate[bot])
- chore\(deps\): update mikefarah/yq action to v4.6.2 [\#2007](https://github.com/pomerium/pomerium/pull/2007) (@renovate[bot])
- fix\(deps\): update google.golang.org/genproto commit hash to 5f0e893 [\#2006](https://github.com/pomerium/pomerium/pull/2006) (@renovate[bot])
- fix\(deps\): update golang.org/x/net commit hash to d523dce [\#2005](https://github.com/pomerium/pomerium/pull/2005) (@renovate[bot])
- fix\(deps\): update module google.golang.org/api to v0.42.0 [\#1989](https://github.com/pomerium/pomerium/pull/1989) (@renovate[bot])
- fix\(deps\): update module github.com/open-policy-agent/opa to v0.27.1 [\#1988](https://github.com/pomerium/pomerium/pull/1988) (@renovate[bot])
- fix\(deps\): update module github.com/hashicorp/go-multierror to v1.1.1 [\#1987](https://github.com/pomerium/pomerium/pull/1987) (@renovate[bot])
- fix\(deps\): update module contrib.go.opencensus.io/exporter/prometheus to v0.3.0 [\#1986](https://github.com/pomerium/pomerium/pull/1986) (@renovate[bot])
- chore\(deps\): update codecov/codecov-action action to v1.3.1 [\#1985](https://github.com/pomerium/pomerium/pull/1985) (@renovate[bot])
- fix\(deps\): update google.golang.org/genproto commit hash to 8812039 [\#1984](https://github.com/pomerium/pomerium/pull/1984) (@renovate[bot])
- fix\(deps\): update golang.org/x/oauth2 commit hash to cd4f82c [\#1983](https://github.com/pomerium/pomerium/pull/1983) (@renovate[bot])
- fix\(deps\): update golang.org/x/crypto commit hash to 513c2a4 [\#1982](https://github.com/pomerium/pomerium/pull/1982) (@renovate[bot])
- fix\(deps\): update module github.com/prometheus/procfs to v0.6.0 [\#1969](https://github.com/pomerium/pomerium/pull/1969) (@renovate[bot])
- fix\(deps\): update module github.com/google/go-cmp to v0.5.5 [\#1968](https://github.com/pomerium/pomerium/pull/1968) (@renovate[bot])
- fix\(deps\): update module github.com/go-redis/redis/v8 to v8.7.1 [\#1967](https://github.com/pomerium/pomerium/pull/1967) (@renovate[bot])
- fix\(deps\): update google.golang.org/genproto commit hash to 9728d6b [\#1966](https://github.com/pomerium/pomerium/pull/1966) (@renovate[bot])
- fix\(deps\): update github.com/nsf/jsondiff commit hash to 6ea3239 [\#1965](https://github.com/pomerium/pomerium/pull/1965) (@renovate[bot])
- fix\(deps\): update module github.com/go-chi/chi to v5 [\#1956](https://github.com/pomerium/pomerium/pull/1956) (@renovate[bot])
- fix\(deps\): update module google.golang.org/grpc to v1.36.0 [\#1955](https://github.com/pomerium/pomerium/pull/1955) (@renovate[bot])
- fix\(deps\): update module go.opencensus.io to v0.23.0 [\#1954](https://github.com/pomerium/pomerium/pull/1954) (@renovate[bot])
- fix\(deps\): update module github.com/lithammer/shortuuid/v3 to v3.0.6 [\#1953](https://github.com/pomerium/pomerium/pull/1953) (@renovate[bot])
- chore\(deps\): update vuepress monorepo to v1.8.2 [\#1952](https://github.com/pomerium/pomerium/pull/1952) (@renovate[bot])
- chore\(deps\): update mikefarah/yq action to v4.6.1 [\#1951](https://github.com/pomerium/pomerium/pull/1951) (@renovate[bot])
- fix\(deps\): update google.golang.org/genproto commit hash to ab064af [\#1950](https://github.com/pomerium/pomerium/pull/1950) (@renovate[bot])
- fix\(deps\): update golang.org/x/net commit hash to e18ecbb [\#1949](https://github.com/pomerium/pomerium/pull/1949) (@renovate[bot])
- chore\(deps\): update yaml v2 to v3 [\#1927](https://github.com/pomerium/pomerium/pull/1927) (@desimone)
- chore\(deps\): update vuepress monorepo to v1.8.1 [\#1891](https://github.com/pomerium/pomerium/pull/1891) (@renovate[bot])
- chore\(deps\): update module spf13/cobra to v1.1.3 [\#1890](https://github.com/pomerium/pomerium/pull/1890) (@renovate[bot])
- chore\(deps\): update module google.golang.org/api to v0.40.0 [\#1889](https://github.com/pomerium/pomerium/pull/1889) (@renovate[bot])
- chore\(deps\): update mikefarah/yq action to v4.5.1 [\#1888](https://github.com/pomerium/pomerium/pull/1888) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to e7f2df4 [\#1887](https://github.com/pomerium/pomerium/pull/1887) (@renovate[bot])
- chore\(deps\): update golang.org/x/oauth2 commit hash to 6667018 [\#1886](https://github.com/pomerium/pomerium/pull/1886) (@renovate[bot])
- chore\(deps\): update module auth0 to v5 [\#1868](https://github.com/pomerium/pomerium/pull/1868) (@renovate[bot])
- chore\(deps\): update module google.golang.org/api to v0.39.0 [\#1867](https://github.com/pomerium/pomerium/pull/1867) (@renovate[bot])
- chore\(deps\): update module go-redis/redis/v8 to v8.5.0 [\#1866](https://github.com/pomerium/pomerium/pull/1866) (@renovate[bot])
- chore\(deps\): update mikefarah/yq action to v4.5.0 [\#1865](https://github.com/pomerium/pomerium/pull/1865) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to bba0dbe [\#1864](https://github.com/pomerium/pomerium/pull/1864) (@renovate[bot])
- chore\(deps\): update golang.org/x/oauth2 commit hash to 0101308 [\#1863](https://github.com/pomerium/pomerium/pull/1863) (@renovate[bot])

## Deployment

- deployment: update get-envoy script and release hooks [\#2112](https://github.com/pomerium/pomerium/pull/2112) (@github-actions[bot])
- deployment: Publish OS packages to cloudsmith [\#2108](https://github.com/pomerium/pomerium/pull/2108) (@github-actions[bot])
- ci: cache build and test binaries [\#1938](https://github.com/pomerium/pomerium/pull/1938) (@desimone)
- ci: go 1.16.x, cached tests [\#1937](https://github.com/pomerium/pomerium/pull/1937) (@desimone)

## Changed

- config related metrics [\#2065](https://github.com/pomerium/pomerium/pull/2065) (@wasaga)
- proxy: support re-proxying request through control plane for kubernetes [\#2051](https://github.com/pomerium/pomerium/pull/2051) (@calebdoxsey)
- add default gitlab url [\#2044](https://github.com/pomerium/pomerium/pull/2044) (@contrun)
- Updating Doc for Pomerium-Dex Exercise [\#2018](https://github.com/pomerium/pomerium/pull/2018) (@dharmendrakariya)
- Add `xff\_num\_trusted\_hops` config option [\#2003](https://github.com/pomerium/pomerium/pull/2003) (@ntoofu)
- envoy: restrict permissions on embedded envoy binary [\#1999](https://github.com/pomerium/pomerium/pull/1999) (@calebdoxsey)
- ci: deploy master to integration environments [\#1973](https://github.com/pomerium/pomerium/pull/1973) (@travisgroth)
- oidc: use groups claim from ID token if present [\#1970](https://github.com/pomerium/pomerium/pull/1970) (@bonifaido)
- config: expose viper policy hooks [\#1947](https://github.com/pomerium/pomerium/pull/1947) (@calebdoxsey)
- ci: deploy latest release to test environment [\#1916](https://github.com/pomerium/pomerium/pull/1916) (@travisgroth)
- logs: strip query string [\#1894](https://github.com/pomerium/pomerium/pull/1894) (@calebdoxsey)
- in-memory service registry [\#1892](https://github.com/pomerium/pomerium/pull/1892) (@wasaga)
- controlplane: maybe fix flaky test [\#1873](https://github.com/pomerium/pomerium/pull/1873) (@calebdoxsey)
- remove generated code from code coverage metrics [\#1857](https://github.com/pomerium/pomerium/pull/1857) (@travisgroth)

## [v0.13.6](https://github.com/pomerium/pomerium/tree/v0.13.6) (2021-04-17)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.13.5...v0.13.6)

## Security

- deps: upgrade envoy to 1.16.3 [\#2096](https://github.com/pomerium/pomerium/pull/2096) (@travisgroth)

## Documentation

- docs: update community slack link [\#2064](https://github.com/pomerium/pomerium/pull/2064) (@github-actions[bot])

## [v0.13.5](https://github.com/pomerium/pomerium/tree/v0.13.5) (2021-04-06)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.13.4...v0.13.5)

## Fixed

- change require\_proxy\_protocol to use\_proxy\_protocol [\#2058](https://github.com/pomerium/pomerium/pull/2058) (@github-actions[bot])

## [v0.13.4](https://github.com/pomerium/pomerium/tree/v0.13.4) (2021-03-31)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.13.3...v0.13.4)

## Security

- proxy: restrict programmatic URLs to localhost [\#2047](https://github.com/pomerium/pomerium/pull/2047) (@travisgroth)
- authenticate: validate signature on /.pomerium, /.pomerium/sign\_in and /.pomerium/sign\_out [\#2046](https://github.com/pomerium/pomerium/pull/2046) (@travisgroth)

## [v0.13.3](https://github.com/pomerium/pomerium/tree/v0.13.3) (2021-03-12)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.13.2...v0.13.3)

## New

- identity: infer email from mail claim [\#1978](https://github.com/pomerium/pomerium/pull/1978) (@github-actions[bot])

## [v0.13.2](https://github.com/pomerium/pomerium/tree/v0.13.2) (2021-02-25)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.13.1...v0.13.2)

## Documentation

- Update data-storage.md [\#1942](https://github.com/pomerium/pomerium/pull/1942) (@github-actions[bot])

## Changed

- proxy: redirect to dashboard for logout [\#1945](https://github.com/pomerium/pomerium/pull/1945) (@github-actions[bot])

## [v0.13.1](https://github.com/pomerium/pomerium/tree/v0.13.1) (2021-02-22)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.13.0...v0.13.1)

## Fixed

- config: fix redirect routes from protobuf [\#1931](https://github.com/pomerium/pomerium/pull/1931) (@github-actions[bot])
- google: fix default provider URL [\#1929](https://github.com/pomerium/pomerium/pull/1929) (@github-actions[bot])

## Documentation

- docs: fix query param name [\#1923](https://github.com/pomerium/pomerium/pull/1923) (@github-actions[bot])
- docs: add breaking sa changes in v0.13 [\#1921](https://github.com/pomerium/pomerium/pull/1921) (@github-actions[bot])
- docs: add v0.13 to docs site menu [\#1914](https://github.com/pomerium/pomerium/pull/1914) (@github-actions[bot])

## Changed

- ci: deploy releases to test environment \(\#1916\) [\#1918](https://github.com/pomerium/pomerium/pull/1918) (@travisgroth)



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*


## [v0.13.0](https://github.com/pomerium/pomerium/tree/v0.13.0) (2021-02-17)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.12.2...v0.13.0)

## Breaking

- authorize: remove admin [\#1833](https://github.com/pomerium/pomerium/pull/1833) (@calebdoxsey)
- remove user impersonation and service account cli [\#1768](https://github.com/pomerium/pomerium/pull/1768) (@calebdoxsey)

## New

- authorize: allow access by user id [\#1850](https://github.com/pomerium/pomerium/pull/1850) (@calebdoxsey)
- authorize: remove DataBrokerData input [\#1847](https://github.com/pomerium/pomerium/pull/1847) (@calebdoxsey)
- opa: format rego files [\#1845](https://github.com/pomerium/pomerium/pull/1845) (@calebdoxsey)
- policy: add new certificate-authority option for downstream mTLS client certificates [\#1835](https://github.com/pomerium/pomerium/pull/1835) (@calebdoxsey)
- metrics: human readable cluster name [\#1834](https://github.com/pomerium/pomerium/pull/1834) (@wasaga)
- upstream endpoints load balancer weights [\#1830](https://github.com/pomerium/pomerium/pull/1830) (@wasaga)
- controlplane: only add listener virtual domains for addresses matching the current TLS domain [\#1823](https://github.com/pomerium/pomerium/pull/1823) (@calebdoxsey)
- authenticate: delay evaluation of OIDC provider [\#1802](https://github.com/pomerium/pomerium/pull/1802) (@calebdoxsey)
- config: require shared key if using redis backed databroker [\#1801](https://github.com/pomerium/pomerium/pull/1801) (@travisgroth)
- upstream health check config [\#1796](https://github.com/pomerium/pomerium/pull/1796) (@wasaga)
- new skip\_xff\_append option [\#1788](https://github.com/pomerium/pomerium/pull/1788) (@wasaga)
- policy: add outlier\_detection [\#1786](https://github.com/pomerium/pomerium/pull/1786) (@calebdoxsey)
- reduce memory usage by handling http/2 coalescing via a lua script [\#1779](https://github.com/pomerium/pomerium/pull/1779) (@calebdoxsey)
- add support for proxy protocol on HTTP listener [\#1777](https://github.com/pomerium/pomerium/pull/1777) (@calebdoxsey)
- config: support redirect actions [\#1776](https://github.com/pomerium/pomerium/pull/1776) (@calebdoxsey)
- config: detect underlying file changes [\#1775](https://github.com/pomerium/pomerium/pull/1775) (@calebdoxsey)
- authenticate: update user info screens [\#1774](https://github.com/pomerium/pomerium/pull/1774) (@desimone)
- jws: remove issuer [\#1754](https://github.com/pomerium/pomerium/pull/1754) (@calebdoxsey)

## Fixed

- redis: fix deletion versioning [\#1874](https://github.com/pomerium/pomerium/pull/1874) (@github-actions[bot])
- rego: handle null [\#1853](https://github.com/pomerium/pomerium/pull/1853) (@calebdoxsey)
- config: fix data race [\#1851](https://github.com/pomerium/pomerium/pull/1851) (@calebdoxsey)
- deployment: set maintainer field in packages [\#1848](https://github.com/pomerium/pomerium/pull/1848) (@travisgroth)
- xds: fix always requiring client certificates [\#1844](https://github.com/pomerium/pomerium/pull/1844) (@calebdoxsey)
- fix go:generate for envoy config [\#1826](https://github.com/pomerium/pomerium/pull/1826) (@calebdoxsey)
- controlplane: only enable STATIC dns when all adresses are IP addresses [\#1822](https://github.com/pomerium/pomerium/pull/1822) (@calebdoxsey)
- config: fix databroker policies [\#1821](https://github.com/pomerium/pomerium/pull/1821) (@calebdoxsey)
- config: fix hot-reloading [\#1820](https://github.com/pomerium/pomerium/pull/1820) (@calebdoxsey)
- Revert "reduce memory usage by handling http/2 coalescing via a lua script" [\#1785](https://github.com/pomerium/pomerium/pull/1785) (@calebdoxsey)
- google: fix nil name [\#1771](https://github.com/pomerium/pomerium/pull/1771) (@calebdoxsey)
- autocert: improve logging [\#1767](https://github.com/pomerium/pomerium/pull/1767) (@travisgroth)

## Documentation

- github: add tag suggestion to checklist [\#1819](https://github.com/pomerium/pomerium/pull/1819) (@desimone)
- docs: add reference to the go-sdk [\#1800](https://github.com/pomerium/pomerium/pull/1800) (@desimone)
- updated host rewrite docs [\#1799](https://github.com/pomerium/pomerium/pull/1799) (@vihardesu)
- docs: update menu for v0.12 [\#1755](https://github.com/pomerium/pomerium/pull/1755) (@travisgroth)
- Update GitLab provider docs [\#1591](https://github.com/pomerium/pomerium/pull/1591) (@bradjones1)
- Fix command in Kubernetes Quick start docs [\#1582](https://github.com/pomerium/pomerium/pull/1582) (@wesleyw72)

## Dependency

- chore\(deps\): update module go.opencensus.io to v0.22.6 [\#1842](https://github.com/pomerium/pomerium/pull/1842) (@renovate[bot])
- chore\(deps\): update module go-redis/redis/v8 to v8.4.11 [\#1841](https://github.com/pomerium/pomerium/pull/1841) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 44e461b [\#1840](https://github.com/pomerium/pomerium/pull/1840) (@renovate[bot])
- chore\(deps\): update golang.org/x/oauth2 commit hash to f9ce19e [\#1839](https://github.com/pomerium/pomerium/pull/1839) (@renovate[bot])
- chore\(deps\): update module stretchr/testify to v1.7.0 [\#1816](https://github.com/pomerium/pomerium/pull/1816) (@renovate[bot])
- chore\(deps\): update module open-policy-agent/opa to v0.26.0 [\#1815](https://github.com/pomerium/pomerium/pull/1815) (@renovate[bot])
- chore\(deps\): update module mitchellh/mapstructure to v1.4.1 [\#1814](https://github.com/pomerium/pomerium/pull/1814) (@renovate[bot])
- chore\(deps\): update module google/uuid to v1.2.0 [\#1813](https://github.com/pomerium/pomerium/pull/1813) (@renovate[bot])
- chore\(deps\): update module google.golang.org/grpc to v1.35.0 [\#1812](https://github.com/pomerium/pomerium/pull/1812) (@renovate[bot])
- chore\(deps\): update module go-redis/redis/v8 to v8.4.10 [\#1811](https://github.com/pomerium/pomerium/pull/1811) (@renovate[bot])
- chore\(deps\): update mikefarah/yq action to v4.4.1 [\#1810](https://github.com/pomerium/pomerium/pull/1810) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 8081c04 [\#1809](https://github.com/pomerium/pomerium/pull/1809) (@renovate[bot])
- chore\(deps\): update golang.org/x/oauth2 commit hash to d3ed898 [\#1808](https://github.com/pomerium/pomerium/pull/1808) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to 5f4716e [\#1807](https://github.com/pomerium/pomerium/pull/1807) (@renovate[bot])
- chore\(deps\): update oidc to v3 [\#1783](https://github.com/pomerium/pomerium/pull/1783) (@desimone)
- chore\(deps\): update vuepress monorepo to v1.8.0 [\#1761](https://github.com/pomerium/pomerium/pull/1761) (@renovate[bot])
- chore\(deps\): update module go-redis/redis/v8 to v8.4.8 [\#1760](https://github.com/pomerium/pomerium/pull/1760) (@renovate[bot])
- chore\(deps\): update mikefarah/yq action to v4.3.1 [\#1759](https://github.com/pomerium/pomerium/pull/1759) (@renovate[bot])
- chore\(deps\): update codecov/codecov-action action to v1.2.1 [\#1758](https://github.com/pomerium/pomerium/pull/1758) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to c7d5778 [\#1757](https://github.com/pomerium/pomerium/pull/1757) (@renovate[bot])
- chore\(deps\): update module google.golang.org/api to v0.38.0 [\#1656](https://github.com/pomerium/pomerium/pull/1656) (@renovate[bot])

## Deployment

- ci: fix usage of env variable in latest tag [\#1791](https://github.com/pomerium/pomerium/pull/1791) (@travisgroth)
- databroker: rename cache service [\#1790](https://github.com/pomerium/pomerium/pull/1790) (@calebdoxsey)
- ci: fix deprecated command in latestTag step [\#1763](https://github.com/pomerium/pomerium/pull/1763) (@travisgroth)

## Changed

- docs: additional load balancing documentation [\#1882](https://github.com/pomerium/pomerium/pull/1882) (@github-actions[bot])
- authenticate: validate origin of signout [\#1881](https://github.com/pomerium/pomerium/pull/1881) (@github-actions[bot])
- config: add CertificateFiles to FileWatcherSource list [\#1880](https://github.com/pomerium/pomerium/pull/1880) (@github-actions[bot])
- ci: enable backporting from forks [\#1854](https://github.com/pomerium/pomerium/pull/1854) (@travisgroth)
- ci: fix version metadata in non-releases [\#1836](https://github.com/pomerium/pomerium/pull/1836) (@travisgroth)
- protobuf: upgrade protoc to 3.14 [\#1832](https://github.com/pomerium/pomerium/pull/1832) (@calebdoxsey)
- Update codeowners [\#1831](https://github.com/pomerium/pomerium/pull/1831) (@travisgroth)
- config: return errors on invalid URLs, fix linting [\#1829](https://github.com/pomerium/pomerium/pull/1829) (@calebdoxsey)
- grpc: use custom resolver [\#1828](https://github.com/pomerium/pomerium/pull/1828) (@calebdoxsey)
- controlplane: return errors in xds build methods [\#1827](https://github.com/pomerium/pomerium/pull/1827) (@calebdoxsey)
- include envoy's proto specs into config.proto [\#1817](https://github.com/pomerium/pomerium/pull/1817) (@wasaga)
- expose all envoy cluster options in policy [\#1804](https://github.com/pomerium/pomerium/pull/1804) (@wasaga)
- autocert: store certificates separately from config certificates [\#1794](https://github.com/pomerium/pomerium/pull/1794) (@calebdoxsey)
- move file change detection before autocert [\#1793](https://github.com/pomerium/pomerium/pull/1793) (@calebdoxsey)
- config: support multiple destination addresses [\#1789](https://github.com/pomerium/pomerium/pull/1789) (@calebdoxsey)
- ci: license check action [\#1773](https://github.com/pomerium/pomerium/pull/1773) (@travisgroth)
- authorize: move impersonation into session/service account [\#1765](https://github.com/pomerium/pomerium/pull/1765) (@calebdoxsey)
## [v0.12.2](https://github.com/pomerium/pomerium/tree/v0.12.2) (2021-02-02)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.12.1...v0.12.2)

## Fixed

- \[Backport 0-12-0\] deployment: set maintainer field in packages [\#1849](https://github.com/pomerium/pomerium/pull/1849) (@github-actions[bot])

## Changed

- \[Backport 0-12-0\] ci: fix usage of env variable in latest tag [\#1806](https://github.com/pomerium/pomerium/pull/1806) (@github-actions[bot])
- \[Backport 0-12-0\] docs: add reference to the go-sdk [\#1803](https://github.com/pomerium/pomerium/pull/1803) (@github-actions[bot])
## [v0.12.1](https://github.com/pomerium/pomerium/tree/v0.12.1) (2021-01-13)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.12.0...v0.12.1)

## Fixed

- \[Backport 0-12-0\] google: fix nil name [\#1772](https://github.com/pomerium/pomerium/pull/1772) (@github-actions[bot])
- \[Backport 0-12-0\] autocert: improve logging [\#1769](https://github.com/pomerium/pomerium/pull/1769) (@travisgroth)

## Documentation

- \[Backport 0-12-0\] docs: update menu for v0.12 [\#1762](https://github.com/pomerium/pomerium/pull/1762) (@github-actions[bot])

## Deployment

- \[Backport 0-12-0\] ci: fix deprecated command in latestTag step [\#1764](https://github.com/pomerium/pomerium/pull/1764) (@github-actions[bot])



## [v0.12.0](https://github.com/pomerium/pomerium/tree/v0.12.0) (2021-01-07)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.11.1...v0.12.0)

## New

- tcp: prevent idle stream timeouts for TCP and Websocket routes [\#1744](https://github.com/pomerium/pomerium/pull/1744) (@calebdoxsey)
- telemetry: add support for datadog tracing [\#1743](https://github.com/pomerium/pomerium/pull/1743) (@calebdoxsey)
- use incremental API for envoy xDS [\#1732](https://github.com/pomerium/pomerium/pull/1732) (@calebdoxsey)
- cli: add version command [\#1726](https://github.com/pomerium/pomerium/pull/1726) (@desimone)
- add TLS flags for TCP tunnel [\#1725](https://github.com/pomerium/pomerium/pull/1725) (@calebdoxsey)
- k8s cmd: use authclient package [\#1722](https://github.com/pomerium/pomerium/pull/1722) (@calebdoxsey)
- internal/controlplane: 0s default timeout for tcp routes [\#1716](https://github.com/pomerium/pomerium/pull/1716) (@travisgroth)
- use impersonate groups if impersonate email is set [\#1701](https://github.com/pomerium/pomerium/pull/1701) (@calebdoxsey)
- unimpersonate button [\#1700](https://github.com/pomerium/pomerium/pull/1700) (@calebdoxsey)
- TCP client command [\#1696](https://github.com/pomerium/pomerium/pull/1696) (@calebdoxsey)
- add support for TCP routes [\#1695](https://github.com/pomerium/pomerium/pull/1695) (@calebdoxsey)
- internal/directory: use gitlab provider url option [\#1689](https://github.com/pomerium/pomerium/pull/1689) (@nghnam)
- improve ca cert error message, use GetCertPool for databroker storage [\#1666](https://github.com/pomerium/pomerium/pull/1666) (@calebdoxsey)
- implement new redis storage backend with go-redis package [\#1649](https://github.com/pomerium/pomerium/pull/1649) (@calebdoxsey)
- authenticate: oidc frontchannel-logout endpoint [\#1586](https://github.com/pomerium/pomerium/pull/1586) (@pflipp)

## Fixed

- remove :443 or :80 from proxy URLs in authclient [\#1733](https://github.com/pomerium/pomerium/pull/1733) (@calebdoxsey)
- tcptunnel: handle invalid http response codes [\#1727](https://github.com/pomerium/pomerium/pull/1727) (@calebdoxsey)
- update azure docs [\#1723](https://github.com/pomerium/pomerium/pull/1723) (@calebdoxsey)
- config: fix ignored yaml fields [\#1698](https://github.com/pomerium/pomerium/pull/1698) (@travisgroth)
- fix concurrency race [\#1675](https://github.com/pomerium/pomerium/pull/1675) (@calebdoxsey)
- don't create users when updating sessions [\#1671](https://github.com/pomerium/pomerium/pull/1671) (@calebdoxsey)

## Documentation

- update google docs [\#1738](https://github.com/pomerium/pomerium/pull/1738) (@calebdoxsey)
- docs: add TCP guide [\#1714](https://github.com/pomerium/pomerium/pull/1714) (@travisgroth)
- docs: tcp support [\#1712](https://github.com/pomerium/pomerium/pull/1712) (@travisgroth)
- docs: replace httpbin with verify [\#1702](https://github.com/pomerium/pomerium/pull/1702) (@desimone)
- docs: fix nginx config [\#1691](https://github.com/pomerium/pomerium/pull/1691) (@desimone)
- remove "see policy" phrase in settings docs [\#1668](https://github.com/pomerium/pomerium/pull/1668) (@calebdoxsey)
- docs: add allowed\_idp\_claims docs [\#1665](https://github.com/pomerium/pomerium/pull/1665) (@travisgroth)
- docs: add v0.11 link to version menu [\#1663](https://github.com/pomerium/pomerium/pull/1663) (@travisgroth)

## Dependency

- chore\(deps\): update module google/uuid to v1.1.4 [\#1729](https://github.com/pomerium/pomerium/pull/1729) (@renovate[bot])
- dev: update linter [\#1728](https://github.com/pomerium/pomerium/pull/1728) (@desimone)
- chore\(deps\): update codecov/codecov-action action to v1.1.1 [\#1720](https://github.com/pomerium/pomerium/pull/1720) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to 6772e93 [\#1719](https://github.com/pomerium/pomerium/pull/1719) (@renovate[bot])
- chore\(deps\): update golang.org/x/crypto commit hash to eec23a3 [\#1718](https://github.com/pomerium/pomerium/pull/1718) (@renovate[bot])
- chore\(deps\): update precommit hook pre-commit/pre-commit-hooks to v3.4.0 [\#1710](https://github.com/pomerium/pomerium/pull/1710) (@renovate[bot])
- chore\(deps\): update module prometheus/client\_golang to v1.9.0 [\#1709](https://github.com/pomerium/pomerium/pull/1709) (@renovate[bot])
- chore\(deps\): update module ory/dockertest/v3 to v3.6.3 [\#1708](https://github.com/pomerium/pomerium/pull/1708) (@renovate[bot])
- chore\(deps\): update module go-redis/redis/v8 to v8.4.4 [\#1707](https://github.com/pomerium/pomerium/pull/1707) (@renovate[bot])
- chore\(deps\): update codecov/codecov-action action to v1.1.0 [\#1706](https://github.com/pomerium/pomerium/pull/1706) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 8c77b98 [\#1705](https://github.com/pomerium/pomerium/pull/1705) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to 986b41b [\#1704](https://github.com/pomerium/pomerium/pull/1704) (@renovate[bot])
- chore\(deps\): update golang.org/x/crypto commit hash to 9d13527 [\#1703](https://github.com/pomerium/pomerium/pull/1703) (@renovate[bot])
- chore\(deps\): update module open-policy-agent/opa to v0.25.2 [\#1685](https://github.com/pomerium/pomerium/pull/1685) (@renovate[bot])
- chore\(deps\): update module go-redis/redis/v8 to v8.4.2 [\#1684](https://github.com/pomerium/pomerium/pull/1684) (@renovate[bot])
- chore\(deps\): update module envoyproxy/go-control-plane to v0.9.8 [\#1683](https://github.com/pomerium/pomerium/pull/1683) (@renovate[bot])
- chore\(deps\): update google.golang.org/genproto commit hash to 40ec1c2 [\#1682](https://github.com/pomerium/pomerium/pull/1682) (@renovate[bot])
- chore\(deps\): update golang.org/x/sync commit hash to 09787c9 [\#1681](https://github.com/pomerium/pomerium/pull/1681) (@renovate[bot])
- chore\(deps\): update golang.org/x/oauth2 commit hash to 08078c5 [\#1680](https://github.com/pomerium/pomerium/pull/1680) (@renovate[bot])
- chore\(deps\): update golang.org/x/net commit hash to ac852fb [\#1679](https://github.com/pomerium/pomerium/pull/1679) (@renovate[bot])
- chore\(deps\): update golang.org/x/crypto commit hash to 5f87f34 [\#1678](https://github.com/pomerium/pomerium/pull/1678) (@renovate[bot])

## Deployment

- ci: upgrade yq syntax for v4 [\#1745](https://github.com/pomerium/pomerium/pull/1745) (@travisgroth)
- deployment: Fix docker and rpm workflows [\#1687](https://github.com/pomerium/pomerium/pull/1687) (@travisgroth)
- ci: fix pomerium-cli rpm name [\#1661](https://github.com/pomerium/pomerium/pull/1661) (@travisgroth)

## Changed

- ci: fix typo in yq image [\#1746](https://github.com/pomerium/pomerium/pull/1746) (@travisgroth)
- fix coverage [\#1741](https://github.com/pomerium/pomerium/pull/1741) (@calebdoxsey)
- fix error wrapping [\#1737](https://github.com/pomerium/pomerium/pull/1737) (@calebdoxsey)
- Revert "set recommended defaults" [\#1735](https://github.com/pomerium/pomerium/pull/1735) (@calebdoxsey)
- set recommended defaults [\#1734](https://github.com/pomerium/pomerium/pull/1734) (@calebdoxsey)
- internal/telemetry/metrics: update redis metrics for go-redis [\#1694](https://github.com/pomerium/pomerium/pull/1694) (@travisgroth)

## [v0.11.1](https://github.com/pomerium/pomerium/tree/v0.11.1) (2020-12-11)

[Full Changelog](https://github.com/pomerium/pomerium/compare/v0.11.0...v0.11.1)

## Fixed

- \[Backport 0-11-0\] fix concurrency race [\#1676](https://github.com/pomerium/pomerium/pull/1676) (@github-actions[bot])
- \[Backport 0-11-0\] don't create users when updating sessions [\#1672](https://github.com/pomerium/pomerium/pull/1672) (@github-actions[bot])

## Documentation

- \[Backport 0-11-0\] remove "see policy" phrase in settings docs [\#1669](https://github.com/pomerium/pomerium/pull/1669) (@github-actions[bot])
- \[Backport 0-11-0\] docs: add allowed\_idp\_claims docs [\#1667](https://github.com/pomerium/pomerium/pull/1667) (@github-actions[bot])
- \[Backport 0-11-0\] docs: add v0.11 link to version menu [\#1664](https://github.com/pomerium/pomerium/pull/1664) (@github-actions[bot])

## Deployment

- \[Backport 0-11-0\] ci: fix pomerium-cli rpm name [\#1662](https://github.com/pomerium/pomerium/pull/1662) (@travisgroth)

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
- deployment: add debug build / container / docs [\#1513](https://github.com/pomerium/pomerium/pull/1513) (@travisgroth)
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
- Okta now requires an additional set of credentials to be used to query for group membership set as a [service account](https://www.pomerium.com/docs/reference/reference.html#identity-provider-service-account).
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
- **Group Support** : The authenticate service now retrieves a user's group membership information during authentication and refresh. This change may require additional identity provider configuration; all of which are described in the [updated docs](https://www.pomerium.com/docs/identity-providers.html). A brief summary of the requirements for each IdP are as follows:

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
[synology tutorial]: ../guides/synology.md
