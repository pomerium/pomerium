import { TableCell, TableRow } from "@mui/material";
import isArray from "lodash/isArray";
import startCase from "lodash/startCase";
import React, { FC } from "react";

import ClaimValue from "./ClaimValue";

export type ClaimRowProps = {
  claimKey: string;
  claimValue: unknown;
};
export const ClaimRow: FC<ClaimRowProps> = ({ claimKey, claimValue }) => {
  return (
    <TableRow>
      <TableCell variant="head">{startCase(claimKey)}</TableCell>
      <TableCell align="left">
        {isArray(claimValue) ? (
          claimValue?.map((v, i) => (
            <React.Fragment key={`${v}`}>
              {i > 0 ? <br /> : <></>}
              <ClaimValue claimKey={claimKey} claimValue={v} />
            </React.Fragment>
          ))
        ) : (
          <ClaimValue claimKey={claimKey} claimValue={claimValue} />
        )}
      </TableCell>
    </TableRow>
  );
};
export default ClaimRow;
