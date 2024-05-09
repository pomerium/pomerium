import { Devices } from "@mui/icons-material";
import {
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
} from "@mui/material";
import React, { FC, ReactNode, useContext } from "react";
import { User, Users } from "react-feather";

import { SubpageContext } from "../context/Subpage";

export interface Subpage {
  icon: ReactNode;
  title: string;
}

export const sectionList: Subpage[] = [
  {
    title: "User",
    icon: <User />,
  },
  {
    title: "Groups Info",
    icon: <Users />,
  },
  {
    title: "Devices Info",
    icon: <Devices />,
  },
];
type UserSidebarContent = {
  close: () => void | null;
};
export const UserSidebarContent: FC<UserSidebarContent> = ({
  close,
}: UserSidebarContent): JSX.Element => {
  const info = useContext(SubpageContext);

  return (
    <List>
      {sectionList.map(({ title, icon }) => {
        return (
          <ListItemButton
            key={"tab " + title}
            selected={title === info.subpage}
            onClick={() => {
              info.setSubpage(title);
              !!close && close();
            }}
          >
            <ListItemIcon>{icon}</ListItemIcon>
            <ListItemText primary={title} />
          </ListItemButton>
        );
      })}
    </List>
  );
};
export default UserSidebarContent;
