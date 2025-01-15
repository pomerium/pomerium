import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Stack,
} from "@mui/material";
import React, { FC, useContext, useEffect, useState } from "react";

import { SubpageContext } from "../context/Subpage";
import { UserInfoData } from "../types";
import GroupDetails from "./GroupDetails";
import SessionDetails from "./SessionDetails";
import SessionDeviceCredentials from "./SessionDeviceCredentials";
import SidebarPage from "./SidebarPage";

type UserInfoPageProps = {
  data: UserInfoData & { page: "DeviceEnrolled" | "UserInfo" };
};
const UserInfoPage: FC<UserInfoPageProps> = ({ data }) => {
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
    <SidebarPage>
      <Dialog open={showDeviceEnrolled} onClose={handleCloseDeviceEnrolled}>
        <DialogTitle>Device Enrolled</DialogTitle>
        <DialogContent>
          <DialogContentText>Device Successfully Enrolled</DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDeviceEnrolled}>OK</Button>
        </DialogActions>
      </Dialog>
      <Stack spacing={3}>
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
    </SidebarPage>
  );
};
export default UserInfoPage;
