import type { FC } from "react";
import React, { createContext, useState } from "react";

export const SUBPAGE_USER = "User Info";
export const SUBPAGE_GROUPS = "Groups";
export const SUBPAGE_DEVICES = "Devices";
export const SUBPAGE_ROUTES = "Routes";

export interface SubpageContextValue {
  subpage: string;
  setSubpage: (subpage: string) => void;
}

export const SubpageContext = createContext<SubpageContextValue>({
  subpage: SUBPAGE_USER,
  setSubpage: () => {},
});

const legacySubpageNames = new Map<string, string>([
  ["User", SUBPAGE_USER],
  ["User Info", SUBPAGE_USER],
  ["Groups Info", SUBPAGE_GROUPS],
  ["Groups", SUBPAGE_GROUPS],
  ["Devices Info", SUBPAGE_DEVICES],
  ["Devices", SUBPAGE_DEVICES],
  ["Routes", SUBPAGE_ROUTES],
]);

export type SubpageContextProviderProps = {
  page: string;
};
export const SubpageContextProvider: FC<SubpageContextProviderProps> = ({
  page,
  children,
}) => {
  const setSubpage = (subpage: string) => {
    location.hash = "subpage=" + encodeURIComponent(subpage);
    setState({ ...state, subpage });
  };
  const hashParams = new URLSearchParams(location.hash.substring(1));
  const legacySubpageParam = hashParams.get("subpage") ?? "";
  const normalizedSubpage = legacySubpageNames.get(legacySubpageParam);

  const initState = {
    subpage:
      page === "DeviceEnrolled"
        ? SUBPAGE_DEVICES
        : page === "Routes"
        ? SUBPAGE_ROUTES
        : normalizedSubpage || SUBPAGE_USER,
    setSubpage,
  };

  const [state, setState] = useState(initState);

  return (
    <SubpageContext.Provider value={state}>{children}</SubpageContext.Provider>
  );
};
