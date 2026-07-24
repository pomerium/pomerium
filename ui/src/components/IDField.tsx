import { Box } from "@mui/material";
import type { FC } from "react";
import React from "react";

export type IDFieldProps = {
  value: string;
};
export const IDField: FC<IDFieldProps> = ({ value }) => {
  return (
    <Box component="span" sx={{ fontFamily: '"DM Mono"', fontSize: "12px" }}>
      {value?.split("")?.map((str, idx) => (
        // A static string split into characters never reorders, so the index
        // is a stable key here.
        // eslint-disable-next-line @eslint-react/no-array-index-key
        <React.Fragment key={idx}>
          {str}
          <wbr />
        </React.Fragment>
      ))}
    </Box>
  );
};
export default IDField;
