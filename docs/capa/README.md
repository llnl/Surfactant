# capa in Pyodide

This code demonstrates how to run [capa](https://github.com/mandiant/capa) entirely in the browser using [Pyodide](https://pyodide.org/).

## Setup

1. **Get the Rules**:
    `capa` needs a set of rules to detect capabilities.

    * Download the standard rules from [capa-rules](https://github.com/mandiant/capa-rules).
    * Recommended to download from a tagged release such as [v9.3.1](https://github.com/mandiant/capa-rules/archive/refs/tags/v9.3.1.zip)
    * Name the file `rules.zip`.
    * Place `rules.zip` in this directory.

2. **Run a Web Server**:
    Because several files need to be fetched during initialization (`worker.js` and `rules.zip`), you cannot open `index.html` directly from the file system. You need to serve it.

    You can use Python to start a web server in this directory:
    ```bash
    python3 -m http.server 8000
    ```

3. **Use it**:
    * Open `http://localhost:8000` in your browser.
    * Wait for initialization (check the status/console for more details).
    * Drop a sample (PE, ELF, etc.) onto the drop zone, or click the load example link.
