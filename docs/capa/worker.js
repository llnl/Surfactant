// worker.js
importScripts("https://cdn.jsdelivr.net/pyodide/v0.29.1/full/pyodide.js");

let pyodide = null;
let rulesReady = false;

// Helpers to communicate with main thread
function log(msg, progress = null) {
    postMessage({ type: 'progress', message: msg, progress: progress });
}

function sendError(msg) {
    postMessage({ type: 'error', message: msg });
}

function sendResult(output) {
    postMessage({ type: 'result', output: output });
}

function sendReady() {
    postMessage({ type: 'ready' });
}

async function init(rulesHash) {
    try {
        log("Loading Pyodide...", 10);
        pyodide = await loadPyodide();

        log("Setting up filesystem...", 15);
        pyodide.FS.mkdir('/cache');
        pyodide.FS.mount(pyodide.FS.filesystems.IDBFS, {}, '/cache');

        await new Promise((resolve, reject) => {
            pyodide.FS.syncfs(true, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // Expose sync for Python
        self.sync_fs = function() {
            pyodide.FS.syncfs(false, (err) => {
               if (err) console.error("Error syncing to IDBFS: " + err);
               else console.log("Synced to IDBFS");
            });
        };

        log("Installing dependencies...", 30);
        await pyodide.loadPackage("micropip");
        const micropip = pyodide.pyimport("micropip");

        const dependencies = [
            { pkg: "tenacity<10.0.0,>=8.2.3", opts: { keep_going: true } },
            { pkg: "markdown-it-py>=2.2.0", opts: { keep_going: true } },
            { pkg: "pyiceberg", opts: { keep_going: true, index_urls: ["https://pypi.anaconda.org/pyodide-nightly/simple"] } },
            { pkg: "pydantic", opts: { keep_going: true, index_urls: ["https://pypi.anaconda.org/pyodide-nightly/simple"] } },
            { pkg: "python-flirt", opts: { keep_going: true, index_urls: ["https://pypi.anaconda.org/pyodide-nightly/simple"] } },
            { pkg: "flare-capa", opts: { keep_going: true } }
        ];

        let progress = 30;
        const step = 40 / dependencies.length;

        for (const dep of dependencies) {
            log(`Installing ${dep.pkg.split(/[<>=]/)[0]}...`, progress);
            const args = [`'${dep.pkg}'`];
            if (dep.opts) {
                if (dep.opts.keep_going !== undefined) {
                    args.push(`keep_going=${dep.opts.keep_going ? 'True' : 'False'}`);
                }
                if (dep.opts.index_urls) {
                    args.push(`index_urls=${JSON.stringify(dep.opts.index_urls)}`);
                }
            }
            await pyodide.runPythonAsync(`
                import micropip
                await micropip.install(${args.join(', ')})
            `);
            progress += step;
        }

        log("Download and install rules...", 70);
        let updatingRules = false;
        try {
            let response = await fetch('rules.zip');
            if (!response.ok) throw new Error("rules.zip not found");
            let buffer = await response.arrayBuffer();

            // Hash check
            const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

            if (rulesHash !== hashHex) {
                console.log("Rules changed. Clearing cache.");
                try {
                    const files = pyodide.FS.readdir('/cache');
                    for (const f of files) {
                        if (f !== '.' && f !== '..') {
                            try { pyodide.FS.unlink('/cache/' + f); } catch(e) {}
                        }
                    }
                } catch(e) {}
                updatingRules = true;
                postMessage({ type: 'rules_hash', hash: hashHex });
            }

            pyodide.FS.writeFile("rules.zip", new Uint8Array(buffer));

            await pyodide.runPythonAsync(`
                import zipfile
                import os

                print("Unzipping rules...")
                with zipfile.ZipFile("rules.zip", 'r') as zip_ref:
                    zip_ref.extractall("/rules")

                # Cleanup macOS hidden files
                count_removed = 0
                for root, dirs, files in os.walk("/rules"):
                    for file in files:
                        if file.startswith("._"):
                            os.remove(os.path.join(root, file))
                            count_removed += 1
                if count_removed > 0:
                    print(f"Removed {count_removed} macOS hidden files (._*)")
            `);

        } catch (e) {
            log("Error loading rules.zip: " + e.message, 70);
            console.error(e);
        }

        if (!updatingRules) {
            log("Loading capa...", 90);
        } else {
            log("Loading capa... (rebuilding rules cache, this may take a bit)", 80);
        }
        await pyodide.runPythonAsync(`
            import sys
            import os
            import json
            import capa.main
            import capa.rules.cache

            capa.rules.cache.get_default_cache_directory = lambda: Path("/tmp/capa-cache")
            os.makedirs("/tmp/capa-cache", exist_ok=True)

            import rich.console
            import contextlib

            original_status = rich.console.Console.status
            def patched_status(self, *args, **kwargs):
                @contextlib.contextmanager
                def noop():
                    yield
                return noop()

            rich.console.Console.status = patched_status

            from pathlib import Path
            import capa.loader
            import capa.rules
            import capa.engine
            import capa.render.json
            import capa.render.default
            import capa.render.verbose
            import capa.render.vverbose
            import capa.features
            from capa.features.common import (
                FORMAT_AUTO, FORMAT_PE, FORMAT_ELF, FORMAT_SC32, FORMAT_SC64, FORMAT_BINEXPORT2, FORMAT_FREEZE,
                OS_AUTO, OS_WINDOWS, OS_LINUX, OS_MACOS, OS_ANDROID
            )

            rules = None

            def load_rules():
                global rules
                try:
                    cache_dir = Path("/cache")
                    print("Loading rules...")
                    rules = capa.rules.get_rules([Path("/rules")], cache_dir=cache_dir, enable_cache=True)
                    print(f"Loaded {len(rules)} rules")
                    import js
                    js.sync_fs()
                    return True
                except Exception as e:
                    print(f"Failed to load rules: {e}")
                    return False

            def scan_file(file_path, input_format, input_os, output_format):
                global rules
                if not rules:
                    if not load_rules():
                        return "Error: Rules not loaded. Please ensure rules.zip is present."

                try:
                    path = Path(file_path)

                    if input_format == FORMAT_AUTO:
                        if path.suffix in ('.sc32', '.raw32'):
                            input_format = FORMAT_SC32
                        elif path.suffix in ('.sc64', '.raw64'):
                            input_format = FORMAT_SC64
                        elif path.suffix in ('.BinExport', '.BinExport2',):
                            input_format = FORMAT_BINEXPORT2
                        elif path.suffix in ('.frz',):
                            input_format = FORMAT_FREEZE

                    extractor = capa.loader.get_extractor(
                        path,
                        input_format,
                        input_os,
                        capa.main.BACKEND_VIV,
                        [],
                        should_save_workspace=False,
                        disable_progress=True
                    )

                    capabilities = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=True)

                    meta = capa.loader.collect_metadata([], path, input_format, input_os, [Path("/rules")], extractor, capabilities)
                    meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities.matches)

                    import io
                    import contextlib

                    with io.StringIO() as buf, contextlib.redirect_stdout(buf):
                        ret = None
                        if output_format == "json":
                            ret = capa.render.json.render(meta, rules, capabilities.matches)
                        elif output_format == "verbose":
                            ret = capa.render.verbose.render(meta, rules, capabilities.matches)
                        elif output_format == "vverbose":
                            ret = capa.render.vverbose.render(meta, rules, capabilities.matches)
                        else:
                            ret = capa.render.default.render(meta, rules, capabilities.matches)
                        output = buf.getvalue()

                    if ret:
                        return ret
                    return output

                except Exception as e:
                    import traceback
                    return f"Error during scan: {e}\\n{traceback.format_exc()}"

            load_rules()
        `);

        // Get version
        const version = await pyodide.runPythonAsync("import capa.version; capa.version.__version__");
        postMessage({ type: 'version', version: version });

        rulesReady = true;
        log("Ready!", 100);
        sendReady();

    } catch (err) {
        sendError(err.message + "\n" + (err.stack || ""));
    }
}

async function runScan(fileData, fileName, inputFormat, inputOS, outputFormat) {
    if (!pyodide || !rulesReady) {
        sendError("System not ready");
        return;
    }

    try {
        const filePath = "/tmp/" + fileName;
        pyodide.FS.writeFile(filePath, new Uint8Array(fileData));

        const output = await pyodide.runPythonAsync(`scan_file("${filePath}", input_format="${inputFormat}", input_os="${inputOS}", output_format="${outputFormat}")`);

        sendResult(output);

        // Cleanup? Optional, but good for memory.
        // try { pyodide.FS.unlink(filePath); } catch(e) {}

    } catch (err) {
        sendError("Scan error: " + err.message);
    }
}

onmessage = function(e) {
    const data = e.data;
    if (data.type === 'init') {
        init(data.rulesHash);
    } else if (data.type === 'scan') {
        runScan(data.fileData, data.fileName, data.inputFormat, data.inputOS, data.outputFormat);
    }
};
