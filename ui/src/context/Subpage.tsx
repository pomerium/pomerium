import React, { FC, createContext, useState } from "react";

export interface SubpageContextValue {
  subpage: string;
  setSubpage: (subpage: string) => void;
}

export const SubpageContext = createContext<SubpageContextValue>({
  subpage: "User",
  setSubpage: (_: string) => {},
});

export type SubpageContextProviderProps = {
  page: string;
};
export const SubpageContextProvider: FC<SubpageContextProviderProps> = ({
  page,
  children,
}) => {
  const setSubpage = (subpage: string) => {
    setState({ ...state, subpage });
  };

  const initState = {
    subpage: page === "DeviceEnrolled" ? "Devices Info" : "User",
    setSubpage,
  };

  const [state, setState] = useState(initState);

  return (
    <SubpageContext.Provider value={state}>{children}</SubpageContext.Provider>
  );
};
