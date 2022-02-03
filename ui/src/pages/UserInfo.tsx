import GroupDetails from "../components/GroupDetails";
import SessionDetails from "../components/SessionDetails";
import SessionDeviceCredentials from "../components/SessionDeviceCredentials";
import UserClaims from "../components/UserClaims";
import UserInfoWelcome from "../components/UserInfoWelcome";
import Container from "@mui/material/Container";
import Stack from "@mui/material/Stack";
import React, { FC } from "react";
import { UserInfoData } from "src/types";

type UserInfoProps = {
  data: UserInfoData;
};
const UserInfo: FC<UserInfoProps> = ({ data }) => {
  return (
    <Container>
      <Stack spacing={3}>
        <UserInfoWelcome user={data?.user} />
        <SessionDetails session={data?.session} />
        <UserClaims user={data?.user} />
        <GroupDetails groups={data?.directoryGroups} />
        <SessionDeviceCredentials
          session={data?.session}
          user={data?.user}
          webAuthnUrl={data?.webAuthnUrl}
        />
      </Stack>
    </Container>
  );
};
export default UserInfo;
