import { styled } from "@mui/material/styles";
import type { CSSProperties } from "@mui/material/styles";

const ToolbarOffset = styled("div")(({ theme }) => ({
  ...(theme.mixins.toolbar as CSSProperties),
}));

export default ToolbarOffset;
