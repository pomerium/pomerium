import Box from "@mui/material/Box";
import React, { FC } from "react";

export type IDFieldProps = {
  value: string;
};
export const IDField: FC<IDFieldProps> = ({ value }) => {
  return (
    <Box component="span" sx={{ fontFamily: '"DM Mono"', fontSize: "12px" }}>
      {value?.split("")?.map((str, idx) => (
        <React.Fragment key={idx}>
          {str}
          <wbr />
        </React.Fragment>
      ))}
    </Box>
  );
};
export default IDField;
