import { DateTime } from "luxon";
import React, { FC } from "react";

const unixSecondTimestampFields = new Set(["exp", "iat", "nbf", "auth_time"]);

type ClaimValueProps = {
  claimKey: string;
  claimValue: unknown;
};
const ClaimValue: FC<ClaimValueProps> = ({ claimKey, claimValue }) => {
  if (unixSecondTimestampFields.has(claimKey)) {
    return <>{DateTime.fromMillis((claimValue as number) * 1000).toISO()}</>;
  }

  return <>{`${claimValue}`}</>;
};
export default ClaimValue;
