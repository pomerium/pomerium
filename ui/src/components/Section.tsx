import { Box, Paper, Stack, Toolbar, Typography } from "@mui/material";
import type { FC } from "react";
import React from "react";

import SectionFooter from "./SectionFooter";

export type SectionProps = React.PropsWithChildren<{
  title: React.ReactNode;
  icon?: React.ReactNode;
  footer?: React.ReactNode;
}>;
export const Section: FC<SectionProps> = ({
  title,
  icon,
  children,
  footer,
}) => {
  return (
    <Paper sx={{ overflow: "hidden" }}>
      <Stack>
        <Toolbar>
          <Typography variant="h4">{title}</Typography>
          {!!icon && (
            <Box sx={{ marginLeft: (theme) => theme.spacing(3) }}>{icon}</Box>
          )}
        </Toolbar>
        <Box sx={{ padding: 3, paddingTop: 0 }}>{children}</Box>
        {footer ? (
          <SectionFooter>
            <Typography variant="caption">{footer}</Typography>
          </SectionFooter>
        ) : (
          <></>
        )}
      </Stack>
    </Paper>
  );
};
export default Section;
