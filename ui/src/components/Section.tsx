import Box from "@mui/material/Box";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";
import styled from "@mui/material/styles/styled";
import React, { FC } from "react";

export const Footer = styled(Box)(({ theme }) => ({
  backgroundColor: theme.palette.grey[100],
  padding: theme.spacing(3)
}));

export type SectionProps = React.PropsWithChildren<{
  title: React.ReactNode;
  icon?: React.ReactNode;
  footer?: React.ReactNode;
}>;
export const Section: FC<SectionProps> = ({
  title,
  icon,
  children,
  footer
}) => {
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
export default Section;
