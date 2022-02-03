import DeviceEnrolledPage from "./components/DeviceEnrolledPage";
import ErrorPage from "./components/ErrorPage";
import Footer from "./components/Footer";
import Header from "./components/Header";
import UserInfoPage from "./components/UserInfoPage";
import WebAuthnRegistrationPage from "./components/WebAuthnRegistrationPage";
import { createTheme } from "./theme";
import { PomeriumData } from "./types";
import Container from "@mui/material/Container";
import CssBaseline from "@mui/material/CssBaseline";
import Stack from "@mui/material/Stack";
import { ThemeProvider } from "@mui/material/styles";
import React, { FC } from "react";

const theme = createTheme();

const App: FC = () => {
  const pomeriumData = (window["POMERIUM_DATA"] || {}) as PomeriumData;
  let body: React.ReactNode = <></>;
  switch (pomeriumData?.page) {
    case "DeviceEnrolled":
      body = <DeviceEnrolledPage />;
      break;
    case "Error":
      body = <ErrorPage data={pomeriumData} />;
      break;
    case "UserInfo":
      body = <UserInfoPage data={pomeriumData} />;
      break;
    case "WebAuthnRegistration":
      body = <WebAuthnRegistrationPage data={pomeriumData} />;
      break;
  }
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Container maxWidth="md" disableGutters>
        <Stack spacing={3}>
          <Header />
          {body}
          <Footer />
        </Stack>
      </Container>
    </ThemeProvider>
  );
};
export default App;
