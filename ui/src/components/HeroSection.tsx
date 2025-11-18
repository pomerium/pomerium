import { Paper, Stack, Typography } from "@mui/material";
import type { FC } from "react";
import React from "react";

export type HeroSectionProps = {
  icon?: React.ReactNode;
  title: React.ReactNode;
  text?: React.ReactNode;
};
export const HeroSection: FC<HeroSectionProps> = ({ icon, title, text }) => {
  return (
    <Paper sx={{ padding: "16px" }}>
      <Stack direction="row" spacing={2}>
        {icon}
        <Stack>
          <Typography variant="h1">{title}</Typography>
          {text ? <Typography>{text}</Typography> : <></>}
        </Stack>
      </Stack>
    </Paper>
  );
};
export default HeroSection;
