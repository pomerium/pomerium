import { User } from "../types";
import ClaimsTable from "./ClaimsTable";
import JwtIcon from "./JwtIcon";
import Section from "./Section";
import React, { FC } from "react";

export type UserClaimsProps = {
  user: User;
};
export const UserClaims: FC<UserClaimsProps> = ({ user }) => {
  return (
    <Section title="User Claims" icon={<JwtIcon />}>
      <ClaimsTable claims={user?.claims} />
    </Section>
  );
};
export default UserClaims;
