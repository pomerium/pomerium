import ClaimsTable from "../components/ClaimsTable";
import JwtIcon from "../components/JwtIcon";
import Box from "@mui/material/Box";
import Container from "@mui/material/Container";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";
import styled from "@mui/material/styles/styled";
import React, { FC } from "react";

const Footer = styled(Box)(({ theme }) => ({
  backgroundColor: theme.palette.grey[100],
  padding: theme.spacing(3)
}));

type SectionProps = React.PropsWithChildren<{
  title: React.ReactNode;
  icon?: React.ReactNode;
  footer?: React.ReactNode;
}>;
const Section: FC<SectionProps> = ({ title, icon, children, footer }) => {
  return (
    <Paper sx={{ overflow: "hidden" }}>
      <Stack>
        <Toolbar>
          <Typography variant="h4" flexGrow={1}>
            {title}
          </Typography>
          {icon ? <Box>{icon}</Box> : <></>}
        </Toolbar>
        <Box sx={{ padding: 3, paddingTop: 0 }}>{children}</Box>
        {footer ? (
          <Footer>
            <Typography variant="caption">{footer}</Typography>
          </Footer>
        ) : (
          <></>
        )}
      </Stack>
    </Paper>
  );
};

type SessionDetailsSectionProps = {
  claims: Record<string, unknown>;
};
const SessionDetailsSection: FC<SessionDetailsSectionProps> = ({ claims }) => {
  return (
    <Section title="Session Details">
      <ClaimsTable claims={claims} />
    </Section>
  );
};

type UserClaimsSectionProps = {
  claims: Record<string, unknown>;
};
const UserClaimsSection: FC<UserClaimsSectionProps> = ({ claims }) => {
  return (
    <Section title="User Claims" icon={<JwtIcon />}>
      <ClaimsTable claims={claims} />
    </Section>
  );
};

const UserInfo: FC = () => {
  return (
    <Container>
      <Stack spacing={3}>
        <SessionDetailsSection claims={{}} />
        <UserClaimsSection claims={{}} />
        <Section
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
        </Paper>
      </Stack>
    </Container>
  );
};
export default UserInfo;
