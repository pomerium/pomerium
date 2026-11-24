import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import IconButton from "@mui/material/IconButton";
import Tooltip from "@mui/material/Tooltip";

type SmallTooltipProps = {
  description: string;
};

export default function SmallTooltip({ description }: SmallTooltipProps) {
  return (
    <Tooltip title={description} arrow>
      <IconButton size="small" sx={{ p: 0 }}>
        <InfoOutlinedIcon fontSize="small" />
      </IconButton>
    </Tooltip>
  );
}
