import type { FC } from "react";
import {
    Tooltip,
    IconButton,
} from "@mui/material";

type SmallTooltipProps = {
    description : string;
}

import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
export const SmallTooltip: FC<SmallTooltipProps> = ({ description }) => {
    return (
        <Tooltip
            title={description}
            arrow
        >
            <IconButton size="small" sx={{ p: 0 }}>
                <InfoOutlinedIcon fontSize="small" />
            </IconButton>
        </Tooltip>
    );
};
