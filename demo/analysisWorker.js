// A worker that creates V86 instance for each analysis type

importScripts("die.js")
importScripts("libv86.js")

// From https://github.com/copy/v86/blob/fc6ffc1734bc223436813692ab431578b906f32a/src/browser/starter.js#L116
function getWasmFunction(bytes) {
    return async env => {
        const { instance } = await WebAssembly.instantiate(bytes, env);
        return instance.exports;
    };
}

self.onmessage = (e) => {
    const data = e.data.data, type = e.data.type;

    const detectItEasy = new DIEInBrowser({
        bios: {
            buffer: data.biosBytes
        },
        initial_state: {
            buffer: data.stateBytes
        },
        wasm_fn: getWasmFunction(data.wasmBytes)
    }, !["strings"].includes(type)); // for 'strings' analysis we don't need to start the emulator

    // Timeout because we need to wait a bit after the emulator starts
    setTimeout(() => {
        detectItEasy.createFile(data.bytes);

        switch (type) {
            case "detects": {
                detectItEasy.fetchDetects(data.flags, data => {
                    self.postMessage({ type, data });
                    self.postMessage({ type: "finished" });
                })
                break;
            }
            case "info": {
                detectItEasy.fetchInfo(data => {
                    self.postMessage({ type, data });
                    self.postMessage({ type: "finished" });
                })
                break;
            }
            case "hashes": {
                detectItEasy.fetchHashes(data => {
                    self.postMessage({ type, data });
                    self.postMessage({ type: "finished" });
                })
                break;
            }
            case "strings": {
                detectItEasy.fetchStrings(data => {
                    self.postMessage({ type, data });
                    self.postMessage({ type: "finished" });
                })
                break;
            }
            case "entropy": {
                detectItEasy.fetchEntropy(data => {
                    self.postMessage({ type, data });
                    self.postMessage({ type: "finished" });
                })
                break;
            }
            case "sections": {
                detectItEasy.fetchSections(data => {
                    self.postMessage({ type, data });
                    self.postMessage({ type: "finished" });
                })
                break;
            }
            case "entrypointPE": {
                detectItEasy.fetchEntrypointPE(data => {
                    self.postMessage({ type, data });
                    self.postMessage({ type: "finished" });
                })
                break;
            }
            case "entrypointELF": {
                detectItEasy.fetchEntrypointELF(data => {
                    self.postMessage({ type, data });
                    self.postMessage({ type: "finished" });
                })
                break;
            }
        }
    }, 200);
}