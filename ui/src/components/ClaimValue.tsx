import isArray from "lodash-es/isArray";
import { Fragment } from "react";

import IDField from "./IDField";

const unixSecondTimestampFields = new Set(["exp", "iat", "nbf", "auth_time"]);

const idFields = new Set(["groups", "jti", "oid", "tid", "wids"]);

type ClaimValueProps = {
  claimKey: string;
  claimValue: unknown;
};
export default function ClaimValue({ claimKey, claimValue }: ClaimValueProps) {
  if (isArray(claimValue)) {
    return (
      <>
        {claimValue?.map((v, i) => (
          <Fragment key={`${v}`}>
            {i > 0 ? <br /> : <></>}
            <ClaimValue claimKey={claimKey} claimValue={v} />
          </Fragment>
        ))}
      </>
    );
  }

  if (unixSecondTimestampFields.has(claimKey)) {
    return <>{new Date((claimValue as number) * 1000).toISOString()}</>;
  }

  if (idFields.has(claimKey)) {
    return <IDField value={`${claimValue}`} />;
  }

  return <>{`${claimValue}`}</>;
}
