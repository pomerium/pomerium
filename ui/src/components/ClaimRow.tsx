import { TableCell, TableRow } from "@mui/material";
import isPlainObject from "lodash/isPlainObject";
import startCase from "lodash/startCase";
import type { FC } from "react";
import React from "react";

import ClaimValue from "./ClaimValue";

export type ClaimRowProps = {
  claimKey: string;
  claimValue: unknown;
};
export const ClaimRow: FC<ClaimRowProps> = ({ claimKey, claimValue }) => {
  if (isPlainObject(claimValue)) {
    return (
      <>
        {Object.entries(claimValue).map(([k, v]) => (
          <ClaimRow
            key={`${claimKey}/${k}`}
            claimKey={`${claimKey} ${k}`}
            claimValue={v}
          />
        ))}
      </>
    );
  }

  return (
    <TableRow>
      <TableCell variant="head">{startCase(claimKey)}</TableCell>
      <TableCell align="left">
        <ClaimValue claimKey={claimKey} claimValue={claimValue} />
      </TableCell>
    </TableRow>
  );
};
export default ClaimRow;
