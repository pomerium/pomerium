import { Devices } from "@mui/icons-material";
import {
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
} from "@mui/material";
import React, { FC, ReactNode, useContext } from "react";
import { Link, User, Users } from "react-feather";

import { SubpageContext } from "../context/Subpage";

export interface Subpage {
  icon: ReactNode;
  title: string;
  pathname: string;
}

export const sectionList: Subpage[] = [
  {
    title: "User",
    icon: <User />,
    pathname: "/.pomerium/",
  },
  {
    title: "Groups Info",
    icon: <Users />,
    pathname: "/.pomerium/",
  },
  {
    title: "Devices Info",
    icon: <Devices />,
    pathname: "/.pomerium/",
  },
  {
    title: "Routes",
    icon: <Link />,
    pathname: "/.pomerium/routes",
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
      {sectionList.map(({ title, icon, pathname }) => {
        return (
          <ListItemButton
            key={"tab " + title}
            selected={title === info.subpage}
            onClick={() => {
              if (location.pathname !== pathname) {
                location.href =
                  pathname + "#subpage=" + encodeURIComponent(title);
                return;
              }
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
