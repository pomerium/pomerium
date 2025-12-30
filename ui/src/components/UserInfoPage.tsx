import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Stack,
} from "@mui/material";
import type { FC } from "react";
import React, { useContext, useEffect, useState } from "react";

import {
  SUBPAGE_DEVICES,
  SUBPAGE_GROUPS,
  SUBPAGE_USER,
  SubpageContext,
} from "../context/Subpage";
import type { UserInfoData } from "../types";
import GroupDetails from "./GroupDetails";
import SessionDetails from "./SessionDetails";
import SessionDeviceCredentials from "./SessionDeviceCredentials";
import SidebarPage from "./SidebarPage";

type UserInfoPageProps = {
  data: UserInfoData & { page: "DeviceEnrolled" | "UserInfo" };
};
const UserInfoPage: FC<UserInfoPageProps> = ({ data }) => {
  const { subpage } = useContext(SubpageContext);
  const isHosted = data?.runtimeFlags?.is_hosted_data_plane;
  const activeSubpage = isHosted ? SUBPAGE_USER : subpage;

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
    <SidebarPage data={data}>
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
        {activeSubpage === SUBPAGE_USER && (
          <SessionDetails session={data?.session} profile={data?.profile} />
        )}

        {!isHosted && activeSubpage === SUBPAGE_GROUPS && (
          <GroupDetails
            isEnterprise={data?.isEnterprise}
            groups={data?.directoryGroups}
          />
        )}

        {!isHosted && activeSubpage === SUBPAGE_DEVICES && (
          <SessionDeviceCredentials
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
