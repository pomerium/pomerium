import { TableCell, TableRow } from "@mui/material";
import { isPlainObject, startCase } from "lodash-es";
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
        {Object.entries(claimValue as Record<string, unknown>).map(([k, v]) => (
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
