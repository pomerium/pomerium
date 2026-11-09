import type {
  IDPSessionData,
  SessionBindingData,
  SessionBindingInfoPageData,
} from "../types";

export type IdpSessGroup = {
  sid: string;
  idpSessions: IDPSessionData[];
  bindings: SessionBindingData[];
};

export function groupIdpSess(data: SessionBindingInfoPageData): {
  groupsBySID: Map<string, IdpSessGroup>;
  bindingsWithoutIdpSess: SessionBindingData[];
} {
  const groupsBySID = new Map<string, IdpSessGroup>();
  const bindingsWithoutIdpSess: SessionBindingData[] = [];

  const groupsByIdpSessID = new Map<string, IdpSessGroup>();
  for (const idpSess of data.idpSessions) {
    const group = groupsBySID.get(idpSess.SID) ?? {
      sid: idpSess.SID,
      idpSessions: [],
      bindings: [],
    };
    group.idpSessions.push(idpSess);
    groupsBySID.set(idpSess.SID, group);
    groupsByIdpSessID.set(idpSess.IDPSessionID, group);
  }

  for (const binding of data.sessionBindings) {
    const group = groupsByIdpSessID.get(binding.IDPSessionID);
    if (group === undefined) {
      bindingsWithoutIdpSess.push(binding);
    } else {
      group.bindings.push(binding);
    }
  }

  return { groupsBySID, bindingsWithoutIdpSess };
}

export function sortIdpSessGroups(
  groupsBySID: Map<string, IdpSessGroup>,
  currentIdpSessID: string,
): IdpSessGroup[] {
  const groups = [...groupsBySID.values()]
    .map((group) => ({
      ...group,
      idpSessions: [...group.idpSessions].sort(newestFirst),
      bindings: [...group.bindings].sort(newestFirst),
    }))
    .sort((a, b) => newestFirst(a.idpSessions[0], b.idpSessions[0]));

  const current = groups.findIndex((group) =>
    group.idpSessions.some((s) => s.IDPSessionID === currentIdpSessID),
  );
  if (current > 0) groups.unshift(...groups.splice(current, 1));
  return groups;
}

function newestFirst(a: { InitiatedAt: string }, b: { InitiatedAt: string }) {
  return initiatedAt(b) - initiatedAt(a);
}

function initiatedAt(item: { InitiatedAt: string }): number {
  const timestamp = new Date(item.InitiatedAt).getTime();
  return Number.isNaN(timestamp) ? 0 : timestamp;
}
