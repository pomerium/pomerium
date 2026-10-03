// OTEL tracing enablement matrix (QA plan: Core.OTEL Tracing /
// "Tracing requires an exporter and an endpoint").
//
// Tracing is on ONLY when otel_traces_exporter is set (to something other than
// none/noop/"") AND one of the endpoint settings is set. The generic endpoint
// must enable Envoy tracing too - ENG-1960 was exactly that combination working
// for Pomerium's spans but not Envoy's - and OTEL_SDK_DISABLED overrides the
// whole config.
//
// Positives run FIRST, as the gate proving the export pipeline works, so a
// "no spans" negative cannot pass just because the pipeline is broken.

import { expect, test } from "@playwright/test";
import {
  expectNoMarkerSpans,
  hasPomeriumSpans,
  ingressSpans,
  waitForMarkerTrace,
} from "../helpers/jaeger.js";
import { hitMarker } from "../helpers/traffic.js";
import { withPomerium } from "../setup/containers.js";
import { JAEGER_OTLP_HTTP_URL } from "../setup/constants.js";
import { tracingConfig } from "../setup/pomerium-config.js";

test.describe("Tracing enablement", () => {
  test("TC-TRC-01: exporter + generic endpoint -> Envoy and Pomerium spans arrive", async () => {
    await withPomerium({ configFile: tracingConfig("trc-full") }, async () => {
      const marker = await hitMarker("trc01");

      // ENG-1960 regression guard: the GENERIC endpoint alone must enable BOTH
      // span families. Pomerium's own spans flush on the SDK's default 5s batch
      // delay (otel_bsp_schedule_delay feeds the Envoy pipeline), so wait for
      // the composed trace rather than the first Envoy-only snapshot.
      const trace = await waitForMarkerTrace(marker, { until: hasPomeriumSpans });
      expect(ingressSpans(trace, marker).length).toBeGreaterThan(0);
    });
  });

  test("TC-TRC-04: traces-specific endpoint form also enables tracing", async () => {
    const configFile = tracingConfig("trc-traces-endpoint", {
      otel_exporter_otlp_endpoint: undefined,
      otel_exporter_otlp_traces_endpoint: JAEGER_OTLP_HTTP_URL,
    });
    await withPomerium({ configFile }, async () => {
      await waitForMarkerTrace(await hitMarker("trc04"));
    });
  });

  test("TC-TRC-02: exporter without any endpoint -> no spans", async () => {
    const configFile = tracingConfig("trc-exporter-only", {
      otel_exporter_otlp_endpoint: undefined,
    });
    await withPomerium({ configFile }, async () => {
      await expectNoMarkerSpans(await hitMarker("trc02"));
    });
  });

  test("TC-TRC-03: endpoint without an exporter -> no spans", async () => {
    const configFile = tracingConfig("trc-endpoint-only", {
      otel_traces_exporter: undefined,
    });
    await withPomerium({ configFile }, async () => {
      await expectNoMarkerSpans(await hitMarker("trc03"));
    });
  });

  test("TC-TRC-05: exporter 'none' disables tracing despite an endpoint", async () => {
    const configFile = tracingConfig("trc-exporter-none", { otel_traces_exporter: "none" });
    await withPomerium({ configFile }, async () => {
      await expectNoMarkerSpans(await hitMarker("trc05"));
    });
  });

  test("TC-TRC-06: OTEL_SDK_DISABLED=true overrides the config", async () => {
    const opts = { configFile: tracingConfig("trc-full"), env: { OTEL_SDK_DISABLED: "true" } };
    await withPomerium(opts, async () => {
      await expectNoMarkerSpans(await hitMarker("trc06"));
    });
  });
});
