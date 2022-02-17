import React, {FC, ReactNode, useContext} from "react";
import {SubpageContext} from "../context/Subpage";
import {List, ListItemButton, ListItemIcon, ListItemText} from "@mui/material";
import {Activity, Gift, User, Users} from "react-feather";
import {Devices} from "@mui/icons-material";

export interface Subpage {
  icon: ReactNode;
  title: string;
}

export const sectionList: Subpage[] = [
  {
    title: 'Welcome',
    icon: <Gift />
  },
  {
    title: 'Session',
    icon: <Activity />
  },
  {
    title: 'Claims',
    icon: <User />
  },
  {
    title: 'Groups',
    icon: <Users />
  },
  {
    title: 'Devices',
    icon: <Devices />
  },
]

export const UserSidebarContent:FC = ():JSX.Element => {

  const info = useContext(SubpageContext);

  return (
    <List>
      {sectionList.map(({title, icon}) => {
        return (
          <ListItemButton
            key={'tab ' + title}
            selected={title === info.subpage}
            onClick={() => info.setSubpage(title)}
          >
            <ListItemIcon>
              {icon}
            </ListItemIcon>
            <ListItemText primary={title} />
          </ListItemButton>
        )
      })}
    </List>
  );
}