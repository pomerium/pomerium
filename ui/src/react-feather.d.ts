// react-feather only ships types for its root barrel; declare the per-icon
// modules so they can be imported directly.
declare module "react-feather/dist/icons/*" {
  import type { Icon } from "react-feather";

  const icon: Icon;
  export default icon;
}
