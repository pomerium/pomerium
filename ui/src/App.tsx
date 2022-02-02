import Header from "./components/Header";
import UserInfo from "./pages/UserInfo";
import { createTheme } from "./theme";
import Container from "@mui/material/Container";
import CssBaseline from "@mui/material/CssBaseline";
import Stack from "@mui/material/Stack";
import { ThemeProvider } from "@mui/material/styles";
import React, { FC } from "react";

const theme = createTheme();

const App: FC = () => {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Container maxWidth="md" disableGutters>
        <Stack spacing={3}>
          <Header />
          <UserInfo />
        </Stack>
      </Container>
    </ThemeProvider>
  );
};
export default App;
