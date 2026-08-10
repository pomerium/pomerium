// Span correctness and sampling (QA plans: Core.OTEL Tracing /
// "Envoy and Pomerium spans both reach the collector" and
// "Sampling and limits are silently clamped").
//
// One request must produce ONE trace carrying spans from both span families:
// Envoy's (service.name "Envoy", resource attribute pomerium.envoy=true,
// operation "ingress: <method> <host><path>") and Pomerium's own services.
// Envoy does not talk to the collector directly - its spans ship over gRPC to
// the control plane and Pomerium forwards them - so their arrival also proves
// that internal hop.
//
// otel_traces_sampler_arg drives ENVOY's random sampling percentage only
// (clamped to 0..1); Pomerium's own tracer providers set no sampler. The
// sampling assertions therefore scope to the Envoy service exclusively, and
// their negative windows only have to outlast Envoy's 1s flush interval.

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

const samplerConfig = (name: string, samplerArg: number) =>
  tracingConfig(name, { otel_traces_sampler_arg: samplerArg });

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
  test("TC-TRC-12: sampler_arg 1.0 -> every request is traced", async () => {
    await withPomerium({ configFile: samplerConfig("trc-sampler-1", 1.0) }, async () => {
      const markers = await hitMarkers("trc12", 3);
      for (const marker of markers) {
        await waitForMarkerTrace(marker);
      }
    });
  });

  test("TC-TRC-11: sampler_arg 0.0 -> no Envoy spans at all", async () => {
    await withPomerium({ configFile: samplerConfig("trc-sampler-0", 0.0) }, async () => {
      await expectNoMarkerSpans(await hitMarkers("trc11", 3), ENVOY_ONLY);
    });
  });

  test("TC-TRC-13: out-of-range sampler_arg values are clamped, not rejected", async () => {
    // 5.0 (a plausible "5 percent") clamps to 1.0 -> fully sampled.
    await withPomerium({ configFile: samplerConfig("trc-sampler-5", 5.0) }, async () => {
      await waitForMarkerTrace(await hitMarker("trc13a"));
    });

    // -1 clamps to 0.0 -> nothing sampled, and startup does NOT fail.
    await withPomerium({ configFile: samplerConfig("trc-sampler-neg1", -1.0) }, async () => {
      await expectNoMarkerSpans(await hitMarker("trc13b"), ENVOY_ONLY);
    });
  });
});
