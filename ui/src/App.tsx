import { Box, CssBaseline, ThemeProvider } from "@mui/material";
import React, { FC, useLayoutEffect } from "react";

import ErrorPage from "./components/ErrorPage";
import Footer from "./components/Footer";
import Header from "./components/Header";
import RoutesPage from "./components/RoutesPage";
import SignInSuccessPage from "./components/SignInSuccessPage";
import SignInVerifyPage from "./components/SignInVerifyPage";
import SignOutConfirmPage from "./components/SignOutConfirmPage";
import SignedOutPage from "./components/SignedOutPage";
import { ToolbarOffset } from "./components/ToolbarOffset";
import UpstreamErrorPage from "./components/UpstreamErrorPage";
import UserInfoPage from "./components/UserInfoPage";
import WebAuthnRegistrationPage from "./components/WebAuthnRegistrationPage";
import { SubpageContextProvider } from "./context/Subpage";
import { createTheme } from "./theme";
import { PageData } from "./types";
import SessionBindingInfoPage from "./components/SessionBindingInfo";

const App: FC = () => {
  const data = (window["POMERIUM_DATA"] || {}) as PageData;
  const primary = data?.primaryColor || "#6F43E7";
  const secondary = data?.secondaryColor || "#49AAA1";
  const theme = createTheme(primary, secondary);
  let body: React.ReactNode = <></>;
  if (
    data?.page === "Error" &&
    data?.statusText?.toLowerCase().includes("upstream") &&
    !data?.statusText?.toLowerCase().includes("local")
  ) {
    data.page = "UpstreamError";
  }
  switch (data?.page) {
    case "UpstreamError":
      body = <UpstreamErrorPage data={data} />;
      break;
    case "Error":
      body = <ErrorPage data={data} />;
      break;
    case "Routes":
      body = <RoutesPage data={data} />;
      break;
    case "SignOutConfirm":
      body = <SignOutConfirmPage data={data} />;
      break;
    case "SignedOut":
      body = <SignedOutPage data={data} />;
      break;
    case "DeviceEnrolled":
    case "UserInfo":
      body = <UserInfoPage data={data} />;
      break;
    case "WebAuthnRegistration":
      body = <WebAuthnRegistrationPage data={data} />;
      break;
    case "SignInVerify":
      body = <SignInVerifyPage data={data} />;
      break;
    case "SignInSuccess":
      body = <SignInSuccessPage data={data} />;
      break;
    case "SessionBindingInfo":
      body = <SessionBindingInfoPage data={data}/>;
      break;
  }

  useLayoutEffect(() => {
    const favicon = document.getElementById(
      "favicon"
    ) as HTMLAnchorElement | null;
    if (favicon) {
      favicon.href = data?.faviconUrl || "/.pomerium/favicon.ico";
    }
    const extraFaviconLinks = document.getElementsByClassName(
      "pomerium_favicon"
    ) as HTMLCollectionOf<HTMLAnchorElement> | null;
    for (const link of extraFaviconLinks) {
      link.style.display = data?.faviconUrl ? "none" : "";
    }
  }, []);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <SubpageContextProvider page={data?.page}>
        <Header
          includeSidebar={data?.page === "UserInfo" || data?.page === "Routes"}
          data={data}
        />
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
        <Footer />
      </SubpageContextProvider>
    </ThemeProvider>
  );
};
export default App;
