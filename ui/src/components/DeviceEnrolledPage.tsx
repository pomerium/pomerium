import HeroSection from "./HeroSection";
import Container from "@mui/material/Container";
import React, { FC } from "react";
import { DeviceEnrolledData } from "src/types";

type DeviceEnrolledPageProps = {
  data: DeviceEnrolledData;
};
const DeviceEnrolledPage: FC<DeviceEnrolledPageProps> = () => {
  return (
    <Container>
      <HeroSection
        title="Device Enrolled"
        text="Device Successfully Enrolled"
      />
    </Container>
  );
};
export default DeviceEnrolledPage;
