import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { groupIdpSess, sortIdpSessGroups } from "../src/lib/bindings.ts";

function idpSess(o) {
  return {
    IDPSessionID: "",
    SID: "",
    ClientAddress: "",
    Resource: "",
    InitiatedAt: "",
    ...o,
  };
}

function binding(o) {
  return {
    IDPSessionID: "",
    SessionBindingID: "",
    Protocol: "",
    Resource: "",
    ClientAddress: "",
    InitiatedAt: "",
    ExpiresAt: "",
    RevokeSessionBindingURL: "",
    HasIdentityBinding: false,
    RevokeIdentityBindingURL: "",
    IsCurrentBrowser: false,
    ...o,
  };
}

function pageData(idpSessions, sessionBindings) {
  return { idpSessions, sessionBindings };
}

describe("groupIdpSess", () => {
  const testCases = [
    {
      name: "shared sid",
      idpSessions: [
        idpSess({ IDPSessionID: "a", SID: "s1" }),
        idpSess({ IDPSessionID: "b", SID: "s1" }),
      ],
      bindings: [binding({ IDPSessionID: "b", SessionBindingID: "x" })],
      wantGroups: { s1: { idpSessions: ["a", "b"], bindings: ["x"] } },
      wantOrphans: [],
    },
    {
      name: "no sid",
      idpSessions: [
        idpSess({ IDPSessionID: "a" }),
        idpSess({ IDPSessionID: "b" }),
      ],
      bindings: [
        binding({ IDPSessionID: "a", SessionBindingID: "x" }),
        binding({ IDPSessionID: "a", SessionBindingID: "y" }),
        binding({ IDPSessionID: "b", SessionBindingID: "z" }),
      ],
      wantGroups: {
        "": { idpSessions: ["a", "b"], bindings: ["x", "y", "z"] },
      },
      wantOrphans: [],
    },
    {
      name: "missing idpsession for binding",
      idpSessions: [idpSess({ IDPSessionID: "a", SID: "s1" })],
      bindings: [binding({ IDPSessionID: "b", SessionBindingID: "x" })],
      wantGroups: { s1: { idpSessions: ["a"], bindings: [] } },
      wantOrphans: ["x"],
    },
  ];

  for (const tc of testCases) {
    test(tc.name, () => {
      const { groupsBySID, bindingsWithoutIdpSess } = groupIdpSess(
        pageData(tc.idpSessions, tc.bindings),
      );
      const got = Object.fromEntries(
        [...groupsBySID].map(([sid, g]) => [
          sid,
          {
            idpSessions: g.idpSessions.map((s) => s.IDPSessionID),
            bindings: g.bindings.map((b) => b.SessionBindingID),
          },
        ]),
      );
      assert.deepEqual(got, tc.wantGroups);
      assert.deepEqual(
        bindingsWithoutIdpSess.map((b) => b.SessionBindingID),
        tc.wantOrphans,
      );
    });
  }
});

describe("sortIdpSessGroups", () => {
  const testCases = [
    {
      name: "newest first",
      idpSessions: [
        idpSess({ IDPSessionID: "old", SID: "s1", InitiatedAt: "2026-01-01" }),
        idpSess({ IDPSessionID: "new", SID: "s2", InitiatedAt: "2026-01-03" }),
      ],
      bindings: [],
      currentIdpSessID: "",
      want: [
        { sid: "s2", idpSessions: ["new"], bindings: [] },
        { sid: "s1", idpSessions: ["old"], bindings: [] },
      ],
    },
    {
      name: "group latest",
      idpSessions: [
        idpSess({ IDPSessionID: "c", SID: "s2", InitiatedAt: "2026-01-03" }),
        idpSess({ IDPSessionID: "a", SID: "s1", InitiatedAt: "2020-01-01" }),
        idpSess({ IDPSessionID: "b", SID: "s1", InitiatedAt: "2026-01-05" }),
      ],
      bindings: [],
      currentIdpSessID: "",
      want: [
        { sid: "s1", idpSessions: ["b", "a"], bindings: [] },
        { sid: "s2", idpSessions: ["c"], bindings: [] },
      ],
    },
    {
      name: "current first",
      idpSessions: [
        idpSess({ IDPSessionID: "a", SID: "s1", InitiatedAt: "2026-01-01" }),
        idpSess({ IDPSessionID: "b", SID: "s2", InitiatedAt: "2026-01-03" }),
        idpSess({ IDPSessionID: "cur", SID: "s3", InitiatedAt: "2020-01-01" }),
      ],
      bindings: [],
      currentIdpSessID: "cur",
      want: [
        { sid: "s3", idpSessions: ["cur"], bindings: [] },
        { sid: "s2", idpSessions: ["b"], bindings: [] },
        { sid: "s1", idpSessions: ["a"], bindings: [] },
      ],
    },
    {
      name: "current shared",
      idpSessions: [
        idpSess({ IDPSessionID: "a", SID: "s1", InitiatedAt: "2026-01-05" }),
        idpSess({ IDPSessionID: "cur", SID: "s2", InitiatedAt: "2020-01-01" }),
        idpSess({ IDPSessionID: "b", SID: "s2", InitiatedAt: "2026-01-01" }),
      ],
      bindings: [],
      currentIdpSessID: "cur",
      want: [
        { sid: "s2", idpSessions: ["b", "cur"], bindings: [] },
        { sid: "s1", idpSessions: ["a"], bindings: [] },
      ],
    },
    {
      name: "bindings newest",
      idpSessions: [
        idpSess({ IDPSessionID: "a", SID: "s1", InitiatedAt: "2026-01-01" }),
      ],
      bindings: [
        binding({
          IDPSessionID: "a",
          SessionBindingID: "x",
          InitiatedAt: "2020-01-01",
        }),
        binding({
          IDPSessionID: "a",
          SessionBindingID: "y",
          InitiatedAt: "2026-01-03",
        }),
        binding({
          IDPSessionID: "a",
          SessionBindingID: "z",
          InitiatedAt: "2023-01-01",
        }),
      ],
      currentIdpSessID: "",
      want: [{ sid: "s1", idpSessions: ["a"], bindings: ["y", "z", "x"] }],
    },
    {
      name: "invalid date",
      idpSessions: [
        idpSess({ IDPSessionID: "bad", SID: "s1", InitiatedAt: "garbled" }),
        idpSess({ IDPSessionID: "ok", SID: "s2", InitiatedAt: "2020-01-01" }),
      ],
      bindings: [
        binding({
          IDPSessionID: "ok",
          SessionBindingID: "x",
          InitiatedAt: "garbled",
        }),
        binding({
          IDPSessionID: "ok",
          SessionBindingID: "y",
          InitiatedAt: "2020-01-01",
        }),
      ],
      currentIdpSessID: "",
      want: [
        { sid: "s2", idpSessions: ["ok"], bindings: ["y", "x"] },
        { sid: "s1", idpSessions: ["bad"], bindings: [] },
      ],
    },
  ];

  for (const tc of testCases) {
    test(tc.name, () => {
      const { groupsBySID } = groupIdpSess(
        pageData(tc.idpSessions, tc.bindings),
      );
      const got = sortIdpSessGroups(groupsBySID, tc.currentIdpSessID).map(
        (g) => ({
          sid: g.sid,
          idpSessions: g.idpSessions.map((s) => s.IDPSessionID),
          bindings: g.bindings.map((b) => b.SessionBindingID),
        }),
      );
      assert.deepEqual(got, tc.want);
    });
  }
});
