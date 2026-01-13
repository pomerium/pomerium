import { Devices } from "@mui/icons-material";
import {
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
} from "@mui/material";
import type { FC, ReactNode } from "react";
import React, { useContext } from "react";
import { Link, Lock, User, Users } from "react-feather";

import {
  SUBPAGE_DEVICES,
  SUBPAGE_GROUPS,
  SUBPAGE_ROUTES,
  SUBPAGE_USER,
  SubpageContext,
} from "../context/Subpage";
import type { SidebarData } from "../types";

export interface Subpage {
  icon: ReactNode;
  title: string;
  pathname: string;
}

const userSection: Subpage = {
  title: SUBPAGE_USER,
  icon: <User />,
  pathname: "/.pomerium/",
};

const groupsSection: Subpage = {
  title: SUBPAGE_GROUPS,
  icon: <Users />,
  pathname: "/.pomerium/",
};

const baseSectionList: Subpage[] = [userSection];

const deviceSection: Subpage = {
  title: SUBPAGE_DEVICES,
  icon: <Devices />,
  pathname: "/.pomerium/",
};

const routesSection: Subpage = {
  title: SUBPAGE_ROUTES,
  icon: <Link />,
  pathname: "/.pomerium/routes",
};

const sshSessionsSection: Subpage = {
  title: "SSH Sessions",
  icon: <Lock />,
  pathname: "/.pomerium/session_binding_info",
};

function getSectionList(data?: SidebarData): Subpage[] {
  if (data?.runtimeFlags?.is_hosted_data_plane) {
    return [userSection, sshSessionsSection];
  }

  const sections = [...baseSectionList];

  if (data?.isEnterprise) {
    sections.push(groupsSection);
  }
  sections.push(deviceSection);
  if (data?.runtimeFlags?.routes_portal !== false) {
    sections.push(routesSection);
  }

  sections.push(sshSessionsSection);
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
