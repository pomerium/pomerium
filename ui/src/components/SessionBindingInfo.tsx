import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import LanguageIcon from "@mui/icons-material/Language";
import {
  Box,
  Button,
  Divider,
  IconButton,
  List,
  ListItem,
  ListItemIcon,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
} from "@mui/material";
import { type FC, Fragment, useState } from "react";

import type {
  IDPSessionData,
  SessionBindingData,
  SessionBindingInfoPageData,
} from "../types";
import Section from "./Section";
import SidebarPage from "./SidebarPage";
import { SmallTooltip } from "./Tooltips";
import { groupIdpSess, sortIdpSessGroups } from "./bindings";

type SessionBindingInfoProps = {
  data: SessionBindingInfoPageData;
};

const SessionBindingInfoPage: FC<SessionBindingInfoProps> = ({ data }) => (
  <SidebarPage data={data}>
    <Section title="Sessions">
      <SessionBindingInfoContent data={data} />
    </Section>
  </SidebarPage>
);

function SessionBindingInfoContent(props: SessionBindingInfoProps) {
  const { data } = props;
  const { groupsBySID, bindingsWithoutIdpSess } = groupIdpSess(data);
  const idpSessGroups = sortIdpSessGroups(
    groupsBySID,
    data.currentIdpSessionId,
  );

  return (
    <List
      disablePadding
      sx={{
        maxHeight: "calc(100dvh - 312px)",
        overflowY: "auto",
        pr: 1.5,
        scrollbarGutter: "stable",
      }}
    >
      {idpSessGroups.map((group, index) => (
        <Fragment key={group.sid}>
          {index > 0 && <Divider />}
          <IDPSessionListItem
            idpSessions={group.idpSessions}
            currentIDPSessionID={data.currentIdpSessionId}
            bindings={group.bindings}
            revokeURL={data.revokeSessionBindingUrl}
            showIDPSessionHeaders={group.sid !== ""}
          />
        </Fragment>
      ))}
      {bindingsWithoutIdpSess.length > 0 && (
        <>
          {idpSessGroups.length > 0 && <Divider />}
          <IDPSessionListItem
            idpSessions={[]}
            currentIDPSessionID={data.currentIdpSessionId}
            bindings={bindingsWithoutIdpSess}
            revokeURL={data.revokeSessionBindingUrl}
            showIDPSessionHeaders={false}
          />
        </>
      )}
    </List>
  );
}

type IDPSessionListItemProps = {
  idpSessions: IDPSessionData[];
  currentIDPSessionID: string;
  bindings: SessionBindingData[];
  revokeURL: string;
  showIDPSessionHeaders: boolean;
};

function IDPSessionListItem(props: IDPSessionListItemProps) {
  const {
    idpSessions: idpSessions,
    currentIDPSessionID,
    bindings,
    revokeURL,
    showIDPSessionHeaders: showIDPSessionHeaders,
  } = props;
  const isCurrentBrowserSession = idpSessions.some(
    (session) => session.IDPSessionID === currentIDPSessionID,
  );

  return (
    <ListItem
      sx={{
        alignItems: "start",
        display: "grid",
        gridTemplateColumns: {
          xs: "40px minmax(0, 1fr) auto",
          sm: "48px minmax(0, 1fr) auto",
        },
        px: 0,
        py: { xs: 2, sm: 2.5 },
      }}
    >
      {showIDPSessionHeaders && (
        <ListItemIcon
          sx={{ color: "primary.main", gridColumn: 1, minWidth: 0, pt: 0.25 }}
        >
          <LanguageIcon fontSize="small" />
        </ListItemIcon>
      )}
      {showIDPSessionHeaders && (
        <Box sx={{ gridColumn: 2, minWidth: 0 }}>
          <Stack
            direction="row"
            sx={{ columnGap: 4, flexWrap: "wrap", rowGap: 1.25 }}
          >
            {idpSessions.map((idpSess) => (
              <Box
                key={idpSess.IDPSessionID}
                sx={{ alignItems: "baseline", display: "flex", gap: 1 }}
              >
                <Typography
                  sx={{ flexShrink: 0, fontWeight: 500 }}
                  variant="subtitle1"
                >
                  <IDPSessionTitle
                    session={idpSess}
                    isCurrentBrowserSession={
                      idpSess.IDPSessionID === currentIDPSessionID
                    }
                  />
                </Typography>
                <Typography color="text.secondary" variant="body2">
                  {idpSess.ClientAddress || "Not recorded"}
                </Typography>
                <Typography color="text.secondary" variant="body2">
                  · Started <RelativeDate timestamp={idpSess.InitiatedAt} />
                </Typography>
              </Box>
            ))}
          </Stack>
        </Box>
      )}
      {showIDPSessionHeaders && isCurrentBrowserSession && (
        <Button
          href="/.pomerium/sign_out"
          size="small"
          color="inherit"
          variant="outlined"
          sx={{ ...sessionActionButtonSx, alignSelf: "center", mr: 2 }}
        >
          LOGOUT
        </Button>
      )}
      {bindings.length > 0 && (
        <Box
          sx={{
            gridColumn: showIDPSessionHeaders ? "2 / -1" : "1 / -1",
            mt: showIDPSessionHeaders ? 2 : 0,
          }}
        >
          <Stack direction="row" sx={{ alignItems: "center" }}>
            <Typography
              color="text.secondary"
              sx={{ fontWeight: 600, letterSpacing: 0.4 }}
              variant="caption"
            >
              BOUND CLIENTS
            </Typography>
          </Stack>
          <SessionBindingsTable bindings={bindings} revokeURL={revokeURL} />
        </Box>
      )}
    </ListItem>
  );
}

type RelativeDateProps = {
  timestamp: string;
};

function RelativeDate({ timestamp }: RelativeDateProps) {
  const [renderedAt] = useState(Date.now);

  if (!timestamp) return <>Not recorded</>;

  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return <>{timestamp}</>;

  const elapsedSeconds = (date.getTime() - renderedAt) / 1000;
  const units = [
    ["y", 365 * 24 * 60 * 60],
    ["mo", 30 * 24 * 60 * 60],
    ["d", 24 * 60 * 60],
    ["h", 60 * 60],
    ["m", 60],
    ["s", 1],
  ] as const;
  const seconds = Math.abs(elapsedSeconds);
  const [unit, secondsPerUnit] =
    units.find(([, s]) => seconds >= s) ?? units[units.length - 1];
  const n = Math.round(seconds / secondsPerUnit);
  const relative = elapsedSeconds < 0 ? `${n}${unit} ago` : `in ${n}${unit}`;

  return (
    <Tooltip title={date.toISOString()}>
      <Box component="span">{relative}</Box>
    </Tooltip>
  );
}

type IDPSessionTitleProps = {
  session: IDPSessionData;
  isCurrentBrowserSession: boolean;
};

function IDPSessionTitle(props: IDPSessionTitleProps) {
  const { session, isCurrentBrowserSession } = props;

  return (
    <>
      {session.Resource}
      {isCurrentBrowserSession && (
        <Box component="span" sx={{ fontWeight: "bold" }}>
          {" "}
          (This browser)
        </Box>
      )}
    </>
  );
}

type SessionBindingsTableProps = {
  bindings: SessionBindingData[];
  revokeURL: string;
};

function SessionBindingsTable(props: SessionBindingsTableProps) {
  const { bindings, revokeURL } = props;

  return (
    <TableContainer
      sx={{
        mt: 0.5,
        overflowX: "auto",
      }}
    >
      <Table
        aria-label="Bound clients"
        size="small"
        sx={{ minWidth: 720, tableLayout: "fixed" }}
      >
        <TableHead>
          <TableRow>
            <TableCell sx={{ width: "auto" }}>CLIENT</TableCell>
            <TableCell align="center" sx={{ width: 160 }}>
              INITIATED AT
            </TableCell>
            <TableCell align="center" sx={{ width: 160 }}>
              EXPIRES AT
            </TableCell>
            <TableCell align="center" sx={{ width: 112 }}>
              ACTION
            </TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {bindings.map((binding) => (
            <TableRow
              key={`${binding.Protocol}:${binding.SessionBindingID}`}
              sx={{
                "&:nth-of-type(odd)": { bgcolor: "action.selected" },
                "&:last-child td": { borderBottom: 0 },
              }}
            >
              <TableCell sx={{ width: "auto" }}>
                <Typography sx={{ fontWeight: 500 }} variant="body2">
                  {binding.Resource}
                </Typography>
                <SessionBindingDetails binding={binding} />
              </TableCell>
              <TableCell align="center" sx={{ width: 160 }}>
                <RelativeDate timestamp={binding.InitiatedAt} />
              </TableCell>
              <TableCell align="center" sx={{ width: 160 }}>
                <RelativeDate timestamp={binding.ExpiresAt} />
              </TableCell>
              <TableCell align="center" sx={{ width: 112 }}>
                <RevokeBindingForm
                  action={revokeURL}
                  bindingID={binding.SessionBindingID}
                  protocol={binding.Protocol}
                  label="REVOKE"
                />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

type SessionBindingDetailsProps = {
  binding: SessionBindingData;
};

function SessionBindingDetails({ binding }: SessionBindingDetailsProps) {
  switch (binding.Protocol.toLowerCase()) {
    case "ssh":
      return <SSHSessionDetails binding={binding} />;
    case "mcp":
      return <MCPSessionDetails binding={binding} />;
    default:
      return <DefaultSessionDetails binding={binding} />;
  }
}

function MCPSessionDetails({ binding }: SessionBindingDetailsProps) {
  return <BindingSummary binding={binding} />;
}

function SSHSessionDetails({ binding }: SessionBindingDetailsProps) {
  return (
    <Stack
      component="span"
      direction="row"
      sx={{ alignItems: "center", columnGap: 0.75, flexWrap: "wrap" }}
    >
      <BindingSummary binding={binding} />
      {binding.DetailsSSH && (
        <>
          <Typography color="text.secondary" component="span" variant="body2">
            ·
          </Typography>
          <SSHFingerprint fingerprint={binding.DetailsSSH.FingerprintID} />
        </>
      )}
    </Stack>
  );
}

function DefaultSessionDetails({ binding }: SessionBindingDetailsProps) {
  return <BindingSummary binding={binding} />;
}

function BindingSummary({ binding }: SessionBindingDetailsProps) {
  const details = [binding.Protocol];
  if (binding.ClientAddress) details.push(binding.ClientAddress);

  return (
    <Typography color="text.secondary" component="span" variant="body2">
      {details.join(" · ")}
    </Typography>
  );
}

type RevokeBindingFormProps = {
  action: string;
  bindingID: string;
  protocol: string;
  label: string;
  disabled?: boolean;
};

const sessionActionButtonSx = {
  bgcolor: "primary.main",
  borderColor: "primary.main",
  borderRadius: "6px",
  color: "primary.contrastText",
  fontSize: "0.8125rem",
  fontWeight: 600,
  lineHeight: 1.5,
  minWidth: 80,
  width: 80,
  px: 1.75,
  py: 0.75,
  textTransform: "none",
  "&:hover": {
    bgcolor: "primary.dark",
    borderColor: "primary.dark",
  },
};

function RevokeBindingForm(props: RevokeBindingFormProps) {
  const { action, bindingID, protocol, label, disabled = false } = props;

  return (
    <Box component="form" action={action} method="POST">
      <input type="hidden" name="sessionBindingID" value={bindingID} />
      <input type="hidden" name="protocol" value={protocol} />
      <Button
        type="submit"
        disabled={disabled}
        size="small"
        color="inherit"
        variant="outlined"
        sx={sessionActionButtonSx}
      >
        {label}
      </Button>
    </Box>
  );
}

type SSHFingerprintProps = {
  fingerprint: string;
};

function SSHFingerprint(props: SSHFingerprintProps) {
  const { fingerprint } = props;

  return (
    <Box
      component="span"
      sx={{ display: "inline-flex", alignItems: "center", minWidth: 0 }}
    >
      <Typography
        color="text.secondary"
        component="span"
        sx={{
          fontFamily: "monospace",
          overflowWrap: "anywhere",
        }}
        variant="caption"
      >
        Fingerprint {fingerprint}
      </Typography>
      <SmallTooltip description="Run `ssh-keygen -l -f <client-pub-key>` to check against this fingerprint" />
      <IconButton
        aria-label="Copy fingerprint"
        size="small"
        onClick={() => navigator.clipboard.writeText(fingerprint)}
      >
        <ContentCopyIcon fontSize="small" />
      </IconButton>
    </Box>
  );
}

export default SessionBindingInfoPage;
