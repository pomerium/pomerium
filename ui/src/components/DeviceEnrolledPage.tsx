import HeroSection from "./HeroSection";
import Container from "@mui/material/Container";
import React, { FC } from "react";
import { DeviceEnrolledPageData } from "src/types";

type DeviceEnrolledPageProps = {
  data: DeviceEnrolledPageData;
};
const DeviceEnrolledPage: FC<DeviceEnrolledPageProps> = () => {
  return (
    <Container maxWidth={false}>
      <HeroSection
        title="Device Enrolled"
        text="Device Successfully Enrolled"
      />
    </Container>
  );
};
export default DeviceEnrolledPage;
