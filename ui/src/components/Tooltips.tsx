import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import { IconButton, Tooltip } from "@mui/material";
import type { FC } from "react";

type SmallTooltipProps = {
  description: string;
};

export const SmallTooltip: FC<SmallTooltipProps> = ({ description }) => {
  return (
    <Tooltip title={description} arrow>
      <IconButton size="small" sx={{ p: 0 }}>
        <InfoOutlinedIcon fontSize="small" />
      </IconButton>
    </Tooltip>
  );
};
