import Box from "@mui/material/Box";
import { Fragment } from "react";

export type IDFieldProps = {
  value: string;
};
export default function IDField({ value }: IDFieldProps) {
  return (
    <Box component="span" sx={{ fontFamily: '"DM Mono"', fontSize: "12px" }}>
      {value?.split("")?.map((str, idx) => (
        // A static string split into characters never reorders, so the index
        // is a stable key here.
        // eslint-disable-next-line @eslint-react/no-array-index-key
        <Fragment key={idx}>
          {str}
          <wbr />
        </Fragment>
      ))}
    </Box>
  );
}
