import Devices from "@mui/icons-material/Devices";
import List from "@mui/material/List";
import ListItemButton from "@mui/material/ListItemButton";
import ListItemIcon from "@mui/material/ListItemIcon";
import ListItemText from "@mui/material/ListItemText";
import type { ReactNode } from "react";
import { use } from "react";
import Link from "react-feather/dist/icons/link";
import Lock from "react-feather/dist/icons/lock";
import User from "react-feather/dist/icons/user";
import Users from "react-feather/dist/icons/users";

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
    title: "Client Bindings",
    icon: <Lock />,
    pathname: "/.pomerium/session_binding_info",
  },
];

function getSectionList(data?: SidebarData): Subpage[] {
  const sections = [...baseSectionList];

  if (data?.runtimeFlags?.routes_portal === false) {
    return sections.filter((section) => section.title !== "Routes");
  }

  return sections;
}
type UserSidebarContentProps = {
  close?: (() => void) | null;
  data?: SidebarData;
};
export default function UserSidebarContent({ close, data }: UserSidebarContentProps) {
  const info = use(SubpageContext);
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
                location.href = pathname + "#subpage=" + encodeURIComponent(title);
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
}
