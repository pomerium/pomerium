import { User } from "../types";
import PersonIcon from "./PersonIcon";
import MuiAvatar from "@mui/material/Avatar";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";
import styled from "@mui/material/styles/styled";
import React, { FC } from "react";

const Avatar = styled(MuiAvatar)(({ theme }) => ({
  backgroundColor: theme.palette.primary.main
}));

export type UserInfoWelcomeProps = {
  user: User;
};
export const UserInfoWelcome: FC<UserInfoWelcomeProps> = ({ user }) => {
  const name = user?.claims?.given_name?.[0] || user?.name;

  return (
    <Paper sx={{ padding: "16px" }}>
      <Stack direction="row" spacing={2}>
        <Avatar sx={{ width: 48, height: 48 }}>
          <PersonIcon />
        </Avatar>
        <Stack>
          <Typography variant="h2">Hi {name}!</Typography>
          <Typography>
            Welcome to the user info endpoint. Here you can view your current
            session details, and authorization context.
          </Typography>
        </Stack>
      </Stack>
    </Paper>
  );
};
export default UserInfoWelcome;
