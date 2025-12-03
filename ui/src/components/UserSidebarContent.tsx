import { Devices } from "@mui/icons-material";
import {
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
} from "@mui/material";
import type { FC, ReactNode } from "react";
import React, { useContext } from "react";
import { Link, User, Users, Lock } from "react-feather";

import { SubpageContext } from "../context/Subpage";
import type { SidebarData } from "../types";

export interface Subpage {
  icon: ReactNode;
  title: string;
  pathname: string;
}

const baseSectionList: Subpage[] = [
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
  {
    title : "Client Bindings",
    icon: <Lock/>,
    pathname : "/.pomerium/session_binding_info"
  },
];

function getSectionList(data?: SidebarData): Subpage[] {
  const sections = [...baseSectionList];

  if (data?.runtimeFlags?.routes_portal === false) {
    return sections.filter((section) => section.title !== "Routes");
  }

  return sections;
}
type UserSidebarContent = {
  close: () => void | null;
  data?: SidebarData;
};
export const UserSidebarContent: FC<UserSidebarContent> = ({
  close,
  data,
}: UserSidebarContent): JSX.Element => {
  const info = useContext(SubpageContext);
  const sectionList = getSectionList(data);

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
              close?.();
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
