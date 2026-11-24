import TableCell from "@mui/material/TableCell";
import TableRow from "@mui/material/TableRow";
import isPlainObject from "lodash-es/isPlainObject";
import startCase from "lodash-es/startCase";

import ClaimValue from "./ClaimValue";

export type ClaimRowProps = {
  claimKey: string;
  claimValue: unknown;
};
export default function ClaimRow({ claimKey, claimValue }: ClaimRowProps) {
  if (isPlainObject(claimValue)) {
    return (
      <>
        {Object.entries(claimValue as Record<string, unknown>).map(([k, v]) => (
          <ClaimRow key={`${claimKey}/${k}`} claimKey={`${claimKey} ${k}`} claimValue={v} />
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
}
