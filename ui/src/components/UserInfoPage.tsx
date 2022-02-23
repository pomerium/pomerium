import { Drawer, useMediaQuery } from "@mui/material";
import Container from "@mui/material/Container";
import Stack from "@mui/material/Stack";
import { useTheme } from "@mui/material/styles";
import React, { FC, useContext } from "react";
import { UserInfoPageData } from "src/types";

import { SubpageContext } from "../context/Subpage";
import GroupDetails from "./GroupDetails";
import SessionDetails from "./SessionDetails";
import SessionDeviceCredentials from "./SessionDeviceCredentials";
import { ToolbarOffset } from "./ToolbarOffset";
import { UserSidebarContent } from "./UserSidebarContent";

type UserInfoPageProps = {
  data: UserInfoPageData;
};
const UserInfoPage: FC<UserInfoPageProps> = ({ data }) => {
  const theme = useTheme();
  const mdUp = useMediaQuery(() => theme.breakpoints.up("md"), {
    defaultMatches: true,
    noSsr: false,
  });
  const { subpage } = useContext(SubpageContext);

  return (
    <Container maxWidth={false}>
      {mdUp && (
        <Drawer
          anchor="left"
          open
          PaperProps={{
            sx: {
              backgroundColor: "neutral.900",
              width: 256,
              height: "100vh",
            },
          }}
          variant="persistent"
        >
          <ToolbarOffset />
          <UserSidebarContent close={null} />
          <ToolbarOffset />
        </Drawer>
      )}
      <Stack
        spacing={3}
        sx={{
          marginLeft: mdUp ? "256px" : "0px",
        }}
      >
        {subpage === "User" && <SessionDetails session={data?.session} />}

        {subpage === "Groups Info" && (
          <GroupDetails groups={data?.directoryGroups} />
        )}

        {subpage === "Devices Info" && (
          <SessionDeviceCredentials
            csrfToken={data?.csrfToken}
            session={data?.session}
            user={data?.user}
            webAuthnCreationOptions={data?.webAuthnCreationOptions}
            webAuthnRequestOptions={data?.webAuthnRequestOptions}
            webAuthnUrl={data?.webAuthnUrl}
          />
        )}
      </Stack>
    </Container>
  );
};
export default UserInfoPage;
