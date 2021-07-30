// generate-console-pages.js

const fs = require("fs");
const yaml = require("js-yaml");

/**
 * This helper script, run by the technical writers, (re)generates markdown
 * documents for the Enterprise reference section. It assumes the existence
 * of `console-settings.yaml`, to be sourced as a build artifact from
 * pomerium/pomerium-console, and `pomerium-console_serve.yaml`, sourced from
 * running `pomerium-console gendocs.
 */

// Functions

/**
 *
 * Import content from /docs/reference/settings.yaml when needed.
 */
const fromOSSettings = (name, keys) => {
  //console.log(keys)
  const asMap = Object.values(OSSettings.settings).map((section) => {
    const subSections = Object.values(section.settings)
    return subSections
  } )
  let result = ''
  for (let i = 0; i < asMap.length; i++ ) {
    for (j = 0; j < asMap[i].length; j++){
      const fixAnchorLinksRegex = /\(\#/g
      const fixHTMLLinksRegex = /\(\/(.+?).html/g
      if (asMap[i][j].name === name) {
        result = asMap[i][j].doc.replace(fixAnchorLinksRegex, "(/reference/readme.md#").replace(fixHTMLLinksRegex, "(/$1.md")
      }
      else if (keys !== null && asMap[i][j].keys && keys.some( key => asMap[i][j].keys.indexOf(key) >= 0)) {
        result = asMap[i][j].doc.replace(fixAnchorLinksRegex, "(/reference/readme.md#").replace(fixHTMLLinksRegex, "(/$1.md")
      } else {
        if (asMap[i][j].settings) {
          for (k = 0; k < asMap[i][j].settings.length; k++) {
            if (asMap[i][j].settings[k].name === name && asMap[i][j].settings[k].doc) {
              result = asMap[i][j].settings[k].doc.replace(fixAnchorLinksRegex, "(/reference/readme.md#").replace(fixHTMLLinksRegex, "(/$1.md")
            }
            else if (keys !== null && asMap[i][j].settings[k].keys && keys.some( key => asMap[i][j].settings[k].keys.indexOf(key) >= 0) && asMap[i][j].settings[k].doc) {
              result = asMap[i][j].settings[k].doc.replace(fixAnchorLinksRegex, "(/reference/readme.md#").replace(fixHTMLLinksRegex, "(/$1.md")
            }
          }
        }
      }
    }
  }
  return result;
}

/**
 *  Import console environment/config options from `pomerium-console_serve.yaml`
 */
const writeConfigPage = (src) => {
  //console.log(`keys from src file: ` + JSON.stringify(src)) // For Debugging
  let path = "./docs/enterprise/reference/config.md";
  console.log(`Generating environment variable docs...\n`);
  let frontmatter = `---
title: Environment Variables
lang: en-US
meta:
    - name: keywords
      content: configuration options settings Pomerium enterprise console
---

# Pomerium Console Environment Variables

The keys listed below can be applied in Pomerium Console's \`config.yaml\` file, or applied as environment variables (in uppercase, replacing \`-\` with \`_\`).

`;
  const keySection = (obj) => {
    //console.log(JSON.stringify(obj.name)) // For Debugging
    let header = `## ` + obj.name + "\n\n";
    let body = `${obj.usage}

**Default value:** \`${obj.default_value ? obj.default_value : `none`}\`
`;
    return header + body;
  };

  let content =
    frontmatter + src.options.map((section) => keySection(section)).join("\n");
  fs.writeFileSync(path, content);
};

/**
 * Read `console-settings.yaml` and write
 * markdown pages under `docs/enterprise/reference`.
 */
const writePage = (setting) => {
  let path =
    "./docs/enterprise/reference/" +
    setting.name.replace(/\s/g, "-").toLowerCase() +
    ".md";
  console.log("Generating", path, "page");

  let frontmatter = `---
title: ${setting.name}
lang: en-US
sidebarDepth: 2
meta:
    - name: keywords
      content: configuration options settings Pomerium enterprise console
---

`;

  let header = "# " + setting.name + "\n" + "\n";
  let body = setting.doc ? setting.doc.toString() + "\n" : "";
  let moreBody = setting.settings
    ? setting.settings
        .map((subsection) => writeSubsection(subsection, 2))
        .join("")
    : "";
  let content = frontmatter + header + body + moreBody + postamble;

  fs.writeFileSync(path, content);
};

/**
 * Called by writePage, this function
 * handles nested settings objects.
 */
const writeSubsection = (subsection, depth) => {
  let subContent = "";
  if (!subsection.name) {
    return;
  }
  if (!subsection.doc) {
    //console.log(subsection)
    //console.log(subsection.keys || "no key")
    subContent =
      fromOSSettings(subsection.name, subsection.keys || null) + "\n";
  }
  let header = "#".repeat(depth) + " " + subsection.name + "\n" + "\n";
  subContent =
    subContent + (subsection.doc ? subsection.doc.toString() + "\n\n" : "");
  subsection.attributes
    ? (subContent = subContent + subsection.attributes.toString())
    : null;
  subsection.settings
    ? (subContent =
        subContent +
        subsection.settings
          .map((turtles) => writeSubsection(turtles, depth + 1))
          .join(""))
    : "";
  return header + subContent;
};

// Main

console.log("Reading console-settings.yaml");

let docs = yaml.load(
  fs.readFileSync("./docs/enterprise/console-settings.yaml", "utf8")
);
let keysFile = yaml.load(
  fs.readFileSync("./docs/enterprise/pomerium-console_serve.yaml", "utf8")
);
let OSSettings = yaml.load(
  fs.readFileSync("./docs/reference/settings.yaml", "utf8")
);
let postamble = docs.postamble

writeConfigPage(keysFile);

docs.settings.map((setting) => {
  writePage(setting);
});
