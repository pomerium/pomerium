import { softShadows } from "./shadows";
import "@fontsource/dm-sans";
import common from "@mui/material/colors/common";
import muiCreateTheme, {
  Theme as MuiTheme,
} from "@mui/material/styles/createTheme";

export const createTheme = (): MuiTheme =>
  muiCreateTheme({
    palette: {
      action: {
        active: "#39256C",
      },
      background: {
        default: "#FBFBFB",
        paper: common.white,
      },
      primary: {
        main: "#6F43E7",
      },
      secondary: {
        main: "#49AAA1",
      },
    },
    shadows: softShadows,
    shape: {
      borderRadius: "16px",
    },
    typography: {
      fontFamily: [
        '"DM Sans"',
        "-apple-system",
        "BlinkMacSystemFont",
        '"Segoe UI"',
        "Roboto",
        '"Helvetica Neue"',
        "Arial",
        "sans-serif",
        '"Apple Color Emoji"',
        '"Segoe UI Emoji"',
        '"Segoe UI Symbol"',
      ].join(","),
      h1: {
        fontSize: "3.052rem",
        fontWeight: 550,
      },
      h2: {
        fontSize: "2.441rem",
        fontWeight: 550,
      },
      h3: {
        fontSize: "1.953rem",
        fontWeight: 550,
      },
      h4: {
        fontSize: "1.563rem",
        fontWeight: 550,
      },
      h5: {
        fontSize: "1.25rem",
        fontWeight: 550,
      },
      h6: {
        fontSize: "1rem",
        fontWeight: 550,
      },
    },
  });
