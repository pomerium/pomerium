import type { FC} from "react";
import React, { createContext, useState } from "react";

export interface SubpageContextValue {
  subpage: string;
  setSubpage: (subpage: string) => void;
}

export const SubpageContext = createContext<SubpageContextValue>({
  subpage: "User",
  setSubpage: () => {},
});

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

  const initState = {
    subpage:
      page === "DeviceEnrolled"
        ? "Devices Info"
        : page === "Routes"
        ? "Routes"
        : hashParams.get("subpage") === "Groups Info"
        ? "Groups Info"
        : hashParams.get("subpage") === "Devices Info"
        ? "Devices Info"
        : "User",
    setSubpage,
  };

  const [state, setState] = useState(initState);

  return (
    <SubpageContext.Provider value={state}>{children}</SubpageContext.Provider>
  );
};
