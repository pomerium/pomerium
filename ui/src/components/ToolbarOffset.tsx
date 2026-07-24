import { styled } from "@mui/material";
import type { CSSProperties } from "@mui/material/styles";

export const ToolbarOffset = styled("div")(({ theme }) => ({
  ...(theme.mixins.toolbar as CSSProperties),
}));
