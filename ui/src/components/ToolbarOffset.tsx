import { styled } from "@mui/material";
import type { CSSObject } from "@mui/material/styles";

export const ToolbarOffset = styled("div")(({ theme }) => ({
  ...(theme.mixins.toolbar as CSSObject),
}));
