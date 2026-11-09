import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";
import type { ReactNode } from "react";

export type HeroSectionProps = {
  icon?: ReactNode;
  title: ReactNode;
  text?: ReactNode;
};
export default function HeroSection({ icon, title, text }: HeroSectionProps) {
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
}
