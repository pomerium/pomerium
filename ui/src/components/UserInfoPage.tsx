import {
  Button,
  Container,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Drawer,
  Stack,
  useMediaQuery,
  useTheme,
} from "@mui/material";
import React, { FC, useContext, useEffect, useState } from "react";

import { SubpageContext } from "../context/Subpage";
import { UserInfoData } from "../types";
import GroupDetails from "./GroupDetails";
import SessionDetails from "./SessionDetails";
import SessionDeviceCredentials from "./SessionDeviceCredentials";
import { ToolbarOffset } from "./ToolbarOffset";
import { UserSidebarContent } from "./UserSidebarContent";

type UserInfoPageProps = {
  data: UserInfoData & { page: "DeviceEnrolled" | "UserInfo" };
};
const UserInfoPage: FC<UserInfoPageProps> = ({ data }) => {
  const theme = useTheme();
  const mdUp = useMediaQuery(() => theme.breakpoints.up("md"), {
    defaultMatches: true,
    noSsr: false,
  });
  const { subpage } = useContext(SubpageContext);

  const [showDeviceEnrolled, setShowDeviceEnrolled] = useState(false);

  useEffect(() => {
    if (data.page === "DeviceEnrolled") {
      setShowDeviceEnrolled(true);
    } else {
      setShowDeviceEnrolled(false);
    }
  }, [data.page]);

  function handleCloseDeviceEnrolled() {
    setShowDeviceEnrolled(false);
  }

  return (
    <Container maxWidth={false}>
      <Dialog open={showDeviceEnrolled} onClose={handleCloseDeviceEnrolled}>
        <DialogTitle>Device Enrolled</DialogTitle>
        <DialogContent>
          <DialogContentText>Device Successfully Enrolled</DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDeviceEnrolled}>OK</Button>
        </DialogActions>
      </Dialog>
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
        {subpage === "User" && (
          <SessionDetails session={data?.session} profile={data?.profile} />
        )}

        {subpage === "Groups Info" && (
          <GroupDetails
            isEnterprise={data?.isEnterprise}
            groups={data?.directoryGroups}
          />
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
