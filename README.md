<h1 align="center"><b>🚀 A Simple DAST Project </b></h1>
<img src="https://i.imgur.com/loqC1Vs.png">

<p align="center">
  <a href="https://www.gnu.org/licenses/gpl-3.0.en.html">
      <img src="https://img.shields.io/badge/license-GPL3-_red.svg">
  </a>
  <a href="https://twitter.com/DiMarcoSK">
    <img src="https://img.shields.io/badge/twitter-%40DiMarcoSK-blue">
  </a>
    <a href="https://github.com/DiMarcoSK/simple_dast/issues?q=is%3Aissue+is%3Aclosed">
    <img src="https://img.shields.io/github/issues-closed-raw/DiMarcoSK/simple_dast">
  </a>
  <a href="https://github.com/DiMarcoSK/simple_dast/wiki">
    <img src="https://img.shields.io/badge/doc-wiki-blue.svg">
  </a>
</p>

This is a Web Application Security project that you can use to discover vulnerabilities and dynamically test applications. Automates the entire process of reconnaissance for you. It outperforms the work of subdomain enumeration along with various vulnerability checks and obtaining maximum information about your target.

### 📋 Prerequisites

* Python 3.8 or higher
* Required packages to run command-line tools: Subfinder, Amass, HttpProbe, Katana, Gau, Nuclei, FFuf, assetfinder, and gospider.

### 🔧 Installation

Clone the GitHub repository:

```shell
$ git clone https://github.com/DiMarcoSK/simple_dast/
$ cd simple_dast
```
Install the dependencies:
```shell
$ pip install -r requirements.txt
```

### 🚀 Usage

To run the scanner, use the following command:

```shell
$ python3 dast.py [TARGET] [OPTIONS]
```

**Example:**

```shell
$ python3 dast.py example.com -t 20 --verbose
```

For more information about the available options, run:
```shell
$ python3 dast.py --help
```

## 🛠️ Built With

* [Python](https://www.python.org/) - Programming language
* [Subfinder](https://github.com/projectdiscovery/subfinder) - Subdomain discovery tool
* [Amass](https://github.com/OWASP/Amass) - Subdomain discovery tool
* [assetfinder](https://github.com/tomnomnom/assetfinder) - Subdomain discovery tool
* [HttpProbe](https://github.com/tomnomnom/httprobe) - Tool to check HTTP(S) services on a set of subdomains
* [Katana](https://github.com/JohnWoodman/katana) - Web page discovery tool
* [Gau](https://github.com/lc/gau) - Web page discovery tool
* [gospider](https://github.com/jaeles-project/gospider) - Web page discovery tool
* [FFuf](https://github.com/ffuf/ffuf) - Web page discovery tool
* [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner

