import DeviceEnrolledPage from "./components/DeviceEnrolledPage";
import ErrorPage from "./components/ErrorPage";
import Footer from "./components/Footer";
import Header from "./components/Header";
import SignOutConfirmPage from "./components/SignOutConfirmPage";
import { ToolbarOffset } from "./components/ToolbarOffset";
import UserInfoPage from "./components/UserInfoPage";
import WebAuthnRegistrationPage from "./components/WebAuthnRegistrationPage";
import { SubpageContextProvider } from "./context/Subpage";
import { createTheme } from "./theme";
import {PageData, UserInfoPageData} from "./types";
import Box from "@mui/material/Box";
import CssBaseline from "@mui/material/CssBaseline";
import { ThemeProvider } from "@mui/material/styles";
import React, { FC } from "react";
import {get} from "lodash";

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
      <SubpageContextProvider>
        <Header includeSidebar={data?.page === "UserInfo"} data={data} />
        <ToolbarOffset />
        <Box sx={{ overflow: "hidden", height: "calc(100vh - 120px)" }}>
          <Box
            sx={{
              overflow: "auto",
              height: "100%",
              paddingTop: theme.spacing(5),
            }}
          >
            {body}
            <ToolbarOffset />
          </Box>
        </Box>
        <Footer pomeriumVersion={get(data, 'pomeriumVersion')} />
      </SubpageContextProvider>
    </ThemeProvider>
  );
};
export default App;
