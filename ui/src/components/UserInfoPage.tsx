import Button from "@mui/material/Button";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogContentText from "@mui/material/DialogContentText";
import DialogTitle from "@mui/material/DialogTitle";
import Stack from "@mui/material/Stack";
import { use, useState } from "react";

import { SubpageContext } from "../context/Subpage";
import type { UserInfoData } from "../types";
import GroupDetails from "./GroupDetails";
import SessionDetails from "./SessionDetails";
import SessionDeviceCredentials from "./SessionDeviceCredentials";
import SidebarPage from "./SidebarPage";

type UserInfoPageProps = {
  data: UserInfoData & { page: "DeviceEnrolled" | "UserInfo" };
};
export default function UserInfoPage({ data }: UserInfoPageProps) {
  const { subpage } = use(SubpageContext);

  const [showDeviceEnrolled, setShowDeviceEnrolled] = useState(data.page === "DeviceEnrolled");

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
        {subpage === "User" && <SessionDetails session={data?.session} profile={data?.profile} />}

        {subpage === "Groups Info" && (
          <GroupDetails isEnterprise={data?.isEnterprise} groups={data?.directoryGroups} />
        )}

        {subpage === "Devices Info" &&
          data?.session &&
          data?.user &&
          data?.webAuthnCreationOptions &&
          data?.webAuthnRequestOptions &&
          data?.webAuthnUrl && (
            <SessionDeviceCredentials
              session={data.session}
              user={data.user}
              webAuthnCreationOptions={data.webAuthnCreationOptions}
              webAuthnRequestOptions={data.webAuthnRequestOptions}
              webAuthnUrl={data.webAuthnUrl}
            />
          )}
      </Stack>
    </SidebarPage>
  );
}
