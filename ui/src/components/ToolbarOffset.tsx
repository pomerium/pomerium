import { styled } from "@mui/material";
import { BaseCSSProperties } from "@mui/material/styles/createMixins";

export const ToolbarOffset = styled("div")(({ theme }) => ({
  ...(theme.mixins.toolbar as BaseCSSProperties),
}));
