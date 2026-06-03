import { Box } from "@mui/material";
import type { FC } from "react";
import React from "react";

export type IDFieldProps = {
  value: string;
};
export const IDField: FC<IDFieldProps> = ({ value }) => {
  return (
    <Box
      component="span"
      sx={{
        fontFamily: '"DM Mono"',
        fontSize: "12px",
        overflowWrap: "anywhere",
      }}
    >
      {value}
    </Box>
  );
};
export default IDField;
