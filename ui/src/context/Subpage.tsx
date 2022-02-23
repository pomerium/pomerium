import React, {createContext, FC, useState} from 'react'

export interface SubpageContextValue {
  subpage: string;
  setSubpage: (subpage: string) => void;
}

export const SubpageContext = createContext<SubpageContextValue>({
  subpage: "User",
  setSubpage: (_: string) => {},
});

export const SubpageContextProvider:FC = ({children}) => {

  const setSubpage = (subpage: string) => {
    setState({...state, subpage})
  }

  const initState = {
    subpage: "User",
    setSubpage
  }

  const [state, setState] = useState(initState)

  return (
    <SubpageContext.Provider value={state}>
      {children}
    </SubpageContext.Provider>
  )
}
