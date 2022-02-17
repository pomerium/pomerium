import DeviceEnrolledPage from "./components/DeviceEnrolledPage";
import ErrorPage from "./components/ErrorPage";
import Footer from "./components/Footer";
import Header from "./components/Header";
import SignOutConfirmPage from "./components/SignOutConfirmPage";
import UserInfoPage from "./components/UserInfoPage";
import WebAuthnRegistrationPage from "./components/WebAuthnRegistrationPage";
import { createTheme } from "./theme";
import { PageData } from "./types";
import Container from "@mui/material/Container";
import CssBaseline from "@mui/material/CssBaseline";
import Stack from "@mui/material/Stack";
import { ThemeProvider } from "@mui/material/styles";
import React, { FC } from "react";

const theme = createTheme();

const App: FC = () => {
  const data = (window["POMERIUM_DATA"] || {}) as PageData;
  let body: React.ReactNode = <></>;
  switch (data?.page) {
    case "DeviceEnrolled":
      body = <DeviceEnrolledPage data={data} />;
      break;
    case "Error":
      body = <ErrorPage data={data} />;
      break;
    case "SignOutConfirm":
      body = <SignOutConfirmPage data={data} />;
      break;
    case "UserInfo":
      body = <UserInfoPage data={data} />;
      break;
    case "WebAuthnRegistration":
      body = <WebAuthnRegistrationPage data={data} />;
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
