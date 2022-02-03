import GroupDetails from "./GroupDetails";
import HeroSection from "./HeroSection";
import PersonIcon from "./PersonIcon";
import SessionDetails from "./SessionDetails";
import SessionDeviceCredentials from "./SessionDeviceCredentials";
import UserClaims from "./UserClaims";
import MuiAvatar from "@mui/material/Avatar";
import Container from "@mui/material/Container";
import Stack from "@mui/material/Stack";
import styled from "@mui/material/styles/styled";
import React, { FC } from "react";
import { UserInfoPageData } from "src/types";

const Avatar = styled(MuiAvatar)(({ theme }) => ({
  backgroundColor: theme.palette.primary.main,
  height: 48,
  width: 48
}));

type UserInfoPageProps = {
  data: UserInfoPageData;
};
const UserInfoPage: FC<UserInfoPageProps> = ({ data }) => {
  const name = data?.user?.claims?.given_name?.[0] || data?.user?.name;
  return (
    <Container>
      <Stack spacing={3}>
        <HeroSection
          icon={
            <Avatar>
              <PersonIcon />
            </Avatar>
          }
          title={<>Hi {name}!</>}
          text={
            <>
              Welcome to the user info endpoint. Here you can view your current
              session details, and authorization context.
            </>
          }
        />
        <SessionDetails session={data?.session} />
        <UserClaims user={data?.user} />
        <GroupDetails groups={data?.directoryGroups} />
        <SessionDeviceCredentials
          csrfToken={data?.csrfToken}
          session={data?.session}
          user={data?.user}
          webAuthnUrl={data?.webAuthnUrl}
        />
      </Stack>
    </Container>
  );
};
export default UserInfoPage;
