import GroupDetails from "./GroupDetails";
import HeroSection from "./HeroSection";
import PersonIcon from "./PersonIcon";
import SessionDetails from "./SessionDetails";
import SessionDeviceCredentials from "./SessionDeviceCredentials";
import UserClaims from "./UserClaims";
import MuiAvatar from "@mui/material/Avatar";
import Container from "@mui/material/Container";
import styled from "@mui/material/styles/styled";
import React, {FC, useContext} from "react";
import { UserInfoPageData } from "src/types";
import {Drawer, useMediaQuery} from "@mui/material";
import { useTheme } from '@mui/material/styles';
import { ToolbarOffset } from "./ToolbarOffset";
import {UserSidebarContent} from "./UserSidebarContent";
import {SubpageContext} from "../context/Subpage";
import Box from "@mui/material/Box";
import Stack from "@mui/material/Stack";

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
  const theme = useTheme();
  const smUp = useMediaQuery(() => theme.breakpoints.up('sm'), {
    defaultMatches: true,
    noSsr: false
  });
  const {subpage} = useContext(SubpageContext);


  return (
    <Container maxWidth={false}>
      {smUp && (
        <Drawer
          anchor="left"
          open
          PaperProps={{
            sx: {
              backgroundColor: 'neutral.900',
              width: 256,
              height: '100vh',
            }
          }}
          variant="persistent"
        >
          <ToolbarOffset />
          <UserSidebarContent />
          <ToolbarOffset />
        </Drawer>
      )}
      <Stack
        spacing={3}
        sx={{
          marginLeft: smUp ? '256px' : '0px',
        }}>
        {(subpage === 'Welcome' || !smUp) && (
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
        )}

        {(subpage === 'Session' || !smUp) && (
          <SessionDetails session={data?.session} />
        )}

        {(subpage === 'Claims' || !smUp) && (
          <UserClaims user={data?.user} />
        )}

        {(subpage === 'Groups' || !smUp) && (
          <GroupDetails groups={data?.directoryGroups} />
        )}

        {(subpage === 'Devices' || !smUp) && (
          <SessionDeviceCredentials
            csrfToken={data?.csrfToken}
            session={data?.session}
            user={data?.user}
            webAuthnUrl={data?.webAuthnUrl}
          />
        )}
      </Stack>
    </Container>
  );
};
export default UserInfoPage;
