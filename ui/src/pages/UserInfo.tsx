import SessionDetails from "../components/SessionDetails";
import UserClaims from "../components/UserClaims";
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
        <SessionDetails session={data?.session} />
        <UserClaims user={data?.user} />
        {/* <Section
          title="Groups"
          footer={
            <>
              Your associated groups are pulled from your{" "}
              <a href="https://www.pomerium.io/docs/identity-providers/">
                identity provider
              </a>
              .
            </>
          }
        ></Section>
        <Paper>
          <Typography variant="h6">Groups</Typography>
        </Paper>
        <Paper>
          <Typography variant="h6">
            Current Session Device Credentials
          </Typography>
        </Paper> */}
      </Stack>
    </Container>
  );
};
export default UserInfo;
