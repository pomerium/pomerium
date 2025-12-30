import "@fontsource/dm-mono";
import "@fontsource/dm-sans";
import type { Theme as MuiTheme } from "@mui/material";
import { createTheme as muiCreateTheme } from "@mui/material";
import common from "@mui/material/colors/common";

import { softShadows } from "./shadows";

export const createTheme = (
  primaryColor: string,
  secondaryColor: string
): MuiTheme => {
  return muiCreateTheme({
    components: {
      MuiBackdrop: {
        styleOverrides: {
          root: {
            backgroundColor: "rgba(68, 56, 102, 0.8)",
          },
        },
      },
      MuiBreadcrumbs: {
        styleOverrides: {
          separator: {
            opacity: "30%",
          },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            backgroundColor: "rgba(0,0,0,0.075)",
          },
        },
      },
      MuiDialog: {
        styleOverrides: {
          paper: {
            padding: 0,
          },
        },
      },
      MuiDialogActions: {
        styleOverrides: {
          root: {
            padding: "16px",
            display: "flex",
            flexFlow: "row nowrap",
            justifyContent: "flex-end",
          },
        },
      },
      MuiDialogContent: {
        styleOverrides: {
          root: { padding: "16px" },
        },
      },
      MuiDialogTitle: {
        styleOverrides: {
          root: {
            display: "flex",
            flexFlow: "row nowrap",
            justifyContent: "space-between",
            alignItems: "center",
            padding: "16px",
          },
        },
      },
      MuiFilledInput: {
        styleOverrides: {
          root: {
            borderRadius: "4px",
          },
        },
      },
      MuiLinearProgress: {
        styleOverrides: {
          root: {
            borderRadius: 3,
            overflow: "hidden",
          },
        },
      },
      MuiListItemIcon: {
        styleOverrides: {
          root: {
            minWidth: 32,
          },
        },
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            borderRadius: "4px",
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: {
            fontWeight: 600,
          },
        },
      },
    },
    palette: {
      action: {
        active: "#39256C",
      },
      background: {
        default: "#FBFBFB",
        paper: common.white,
      },
      primary: {
        main: primaryColor,
      },
      secondary: {
        main: secondaryColor,
      },
    },
    shadows: softShadows,
    shape: {
      borderRadius: 16,
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
};
