import { createRoot } from "react-dom/client";

import App from "./App";
import type { PageData } from "./types";

declare global {
  interface Window {
    POMERIUM_DATA?: PageData;
  }
}

const root = createRoot(document.getElementById("root")!);
root.render(<App />);
