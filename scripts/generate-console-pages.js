// generate-console-pages.js
const fs = require('fs');
const yaml = require('js-yaml');


// Functions
const writePage = (setting) => {
    console.log('Generating ', setting.name, " page")
    let frontmatter = `---
title: ${setting.name}
lang: en-US
sidebarDepth: 2
meta:
    - name: keywords
      content: configuration options settings Pomerium enterprise console
---

`
    let path = './docs/enterprise/reference/' + setting.name.replace(/\s/g, '-').toLowerCase() + ".md"
        console.log("path=", path) //For Debugging
    let header = '# ' + setting.name + '\n' + '\n'
    let body = setting.doc ? setting.doc.toString() + '\n' : ''
    let moreBody = setting.settings ? setting.settings.map(subsection => writeSubsection(subsection, 2)).join('') : ''

    let content = frontmatter + header + body + moreBody
    fs.writeFileSync(path, content)

}

const writeSubsection = (subsection, depth) => {
    if (!subsection.name) {
        return
    }
    let header = '#'.repeat(depth) + ' ' + subsection.name + '\n' + '\n'
    let subContent = subsection.doc ? subsection.doc.toString() + '\n' : ''
    subsection.attributes ? subContent = subContent + subsection.attributes.toString() : null
    subsection.settings ? subContent = subContent + subsection.settings.map(turtles => writeSubsection(turtles, depth + 1)).join('') : ''
    return header + subContent
}

// Main

console.log("Reading console-settings.yaml")

let docs = yaml.load(fs.readFileSync('./docs/enterprise/console-settings.yaml', 'utf8'))

docs.settings.map( setting => {
    writePage(setting)    
})

