import React, { FC } from "react";

import IDField from "./IDField";

const unixSecondTimestampFields = new Set(["exp", "iat", "nbf", "auth_time"]);

const idFields = new Set(["groups", "jti", "oid", "tid", "wids"]);

type ClaimValueProps = {
  claimKey: string;
  claimValue: unknown;
};
const ClaimValue: FC<ClaimValueProps> = ({ claimKey, claimValue }) => {
  if (unixSecondTimestampFields.has(claimKey)) {
    return <>{new Date((claimValue as number) * 1000).toISOString()}</>;
  }

  if (idFields.has(claimKey)) {
    return <IDField value={`${claimValue}`} />;
  }

  return <>{`${claimValue}`}</>;
};
export default ClaimValue;
