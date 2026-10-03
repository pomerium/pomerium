// Span correctness and sampling (QA plan: Core.OTEL Tracing /
// "Envoy and Pomerium spans both reach the collector").
//
// One request must produce ONE trace carrying both span families: Envoy's
// (pomerium.envoy=true, operation "ingress: <method> <host><path>") and
// Pomerium's own services. Envoy does not reach the collector directly - its
// spans ship over gRPC to the control plane - so their arrival proves that hop too.
//
// otel_traces_sampler_arg drives ENVOY's sampling percentage only; Pomerium's
// tracer providers set no sampler. So the sampling assertion scopes to Envoy
// alone, and its negative window only has to outlast Envoy's 1s flush.

import { expect, test } from "@playwright/test";
import {
  ENVOY_SERVICE,
  envoyProcessOf,
  expectNoMarkerSpans,
  hasPomeriumSpans,
  ingressSpans,
  waitForMarkerTrace,
} from "../helpers/jaeger.js";
import { hitMarker, hitMarkers } from "../helpers/traffic.js";
import { withPomerium } from "../setup/containers.js";
import { tracingConfig } from "../setup/pomerium-config.js";

/** Envoy flushes on the configured 1s batch delay; 3s is a 3x margin. */
const ENVOY_ONLY = { services: [ENVOY_SERVICE], windowMs: 3_000 };

test.describe("Span correctness", () => {
  test("TC-TRC-10: one request -> one trace with both Envoy and Pomerium spans", async () => {
    await withPomerium({ configFile: tracingConfig("trc-full") }, async () => {
      const marker = await hitMarker("trc10");
      // Envoy's spans and Pomerium's own spans flush on different schedules
      // (the config's 1s batch delay vs the SDK's default 5s), so poll until
      // the trace contains BOTH families rather than asserting on the first
      // (Envoy-only) snapshot. A single trace id carrying both is the point.
      const trace = await waitForMarkerTrace(marker, { until: hasPomeriumSpans });

      expect(ingressSpans(trace, marker).length).toBeGreaterThan(0);

      // Envoy spans are told apart at the collector by a static resource
      // attribute rather than by span shape.
      const envoyTag = (envoyProcessOf(trace)?.tags ?? []).find((t) => t.key === "pomerium.envoy");
      expect(String(envoyTag?.value), "Envoy process resource attributes").toBe("true");
    });
  });
});

test.describe("Sampling (otel_traces_sampler_arg, Envoy scope)", () => {
  test("TC-TRC-11: sampler_arg 0.0 -> no Envoy spans at all", async () => {
    const configFile = tracingConfig("trc-sampler-0", { otel_traces_sampler_arg: 0.0 });
    await withPomerium({ configFile }, async () => {
      await expectNoMarkerSpans(await hitMarkers("trc11", 3), ENVOY_ONLY);
    });
  });
});
