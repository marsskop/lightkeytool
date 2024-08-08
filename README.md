# lightkeytool

A lightweight GO implementation of Java [keytool](https://docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html) that does not require an installation of Java JDK.

## Installation
1. Download the latest version of the application from the [releases](https://github.com/marsskop/lightkeytool/releases) page.
2. Rename the downloaded file to `lightkeytool`.
3. Add execute permissions to the binary. E.g., on Linux and Mac: `chmod u+x lightkeytool`.
4. Put the binary in you `PATH`. E.g., on Linux and Mac: `mv lightkeytool /usr/local/bin/lightkeytool`.

## Help Output
```bash
lightkeytool --help
```
```
A lightweight CLI implementation of keytool that requires no Java JDK to be installed.

Usage:
  lightkeytool [command]

Available Commands:
  completion     Generate the autocompletion script for the specified shell
  exportcert     Export data
  help           Help about any command
  importkeystore Import contents from another keystore

Flags:
  -h, --help      help for lightkeytool
  -v, --verbose   verbose output
      --version   version for lightkeytool

Use "lightkeytool [command] --help" for more information about a command.
```
<!-- ## Usage
TODO -->

## Development Setup
> Make sure that you have [downloaded](https://go.dev/dl/) and installed **Go**. Version 1.22 or higher is required.
```bash
git clone https://github.com/marsskop/lightkeytool.git
cd lightkeytool
go run main.go
```

<!-- ## Contributing
TODO -->

<!-- ## Links
TODO -->

## License
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](https://www.tldrlegal.com/license/mit-license)