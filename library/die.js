class DIEInBrowser {
    static SHARED_FILE_NAME = "file.bin";
    static SHARED_FILE_PATH = `/mnt/${DIEInBrowser.SHARED_FILE_NAME}`;
    static DIE_BASE_COMMAND = "./run_diec.sh";

    constructor(config, startEmulator) {
        this.emulator = startEmulator ? new V86({
            memory_size: 128 * 1024 * 1024,
            autostart: true,
            filesystem: {},
            disable_keyboard: true,
            disable_mouse: true,
            ...config
        }) : null;
    }

    // Runs command in the emulator
    runCommand(command, callback) {
        if (!this.emulator) return;

        // Sending command
        this.emulator.serial0_send(command + "\n");

        // Creating temporary serial output listener

        let buffer = "";

        const serialOutputListener = (byte) => {
            const char = String.fromCharCode(byte);
            buffer += char;

            // Checking if there's sh marker
            if (buffer.endsWith("# ")) {
                // Return only program output
                callback(buffer.split(/\r?\n/).slice(1, -1).join("\n"));
                this.emulator.remove_listener("serial0-output-byte", serialOutputListener);
            }
        };

        this.emulator.add_listener("serial0-output-byte", serialOutputListener);
    }

    // Creates file in the emulator
    createFile(bytes) {
        this.fileBytes = bytes;

        if (!this.emulator) return;

        const sharedName = DIEInBrowser.SHARED_FILE_NAME;
        this.emulator.create_file(sharedName, bytes);
    }

    // Fetches file sections, or returns null if there are none (requires emulator)
    fetchSections(callback) {
        if (!this.emulator) return;

        this.runCommand(`${DIEInBrowser.DIE_BASE_COMMAND} ${DIEInBrowser.SHARED_FILE_PATH} -j -S "IMAGE_SECTION_HEADER"`, methodOutput => {
            try {
                methodOutput = JSON.parse(methodOutput.slice(methodOutput.indexOf("{")).trimStart());
                methodOutput = methodOutput?.data;

                callback(methodOutput);
            } catch (e) {
                callback({
                    error: String(e),
                    raw: methodOutput
                });
            }
        });
    }

    // Fetches PE file entrypoint, or returns null if file isn't PE (requires emulator)
    fetchEntrypointPE(callback) {
        if (!this.emulator) return;

        this.runCommand(`${DIEInBrowser.DIE_BASE_COMMAND} ${DIEInBrowser.SHARED_FILE_PATH} -j -S "IMAGE_NT_HEADERS"`, methodOutput => {
            try {
                methodOutput = JSON.parse(methodOutput.slice(methodOutput.indexOf("{")).trimStart());
                methodOutput = methodOutput?.data;

                if (methodOutput) {
                    let baseAddress = "", entrypoint = "";
                    if (methodOutput?.IMAGE_NT_HEADERS?.IMAGE_OPTIONAL_HEADER?.AddressOfEntryPoint) {
                        entrypoint = methodOutput.IMAGE_NT_HEADERS.IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint;
                    }
                    if (methodOutput?.IMAGE_NT_HEADERS?.IMAGE_OPTIONAL_HEADER?.ImageBase) {
                        baseAddress = methodOutput.IMAGE_NT_HEADERS.IMAGE_OPTIONAL_HEADER.ImageBase;
                    }
                    callback({
                        "Base address": baseAddress,
                        "Entry point": entrypoint
                    });
                } else {
                    callback(null);
                }
            } catch (e) {
                callback({
                    error: String(e),
                    raw: methodOutput
                });
            }
        });
    }

    // Fetches ELF file entrypoint, or returns null if file isn't ELF (requires emulator)
    fetchEntrypointELF(callback) {
        if (!this.emulator) return;

        this.runCommand(`${DIEInBrowser.DIE_BASE_COMMAND} ${DIEInBrowser.SHARED_FILE_PATH} -j -S "Elf_Ehdr"`, methodOutput => {
            try {
                methodOutput = JSON.parse(methodOutput.slice(methodOutput.indexOf("{")).trimStart());
                methodOutput = methodOutput?.data;

                if (methodOutput?.Elf_Ehdr?.entry) {
                    callback({
                        "Entry point": methodOutput.Elf_Ehdr.entry
                    });
                } else {
                    callback(null);
                }
            } catch (e) {
                callback({
                    error: String(e),
                    raw: methodOutput
                });
            }
        });
    }

    // Fetches file detects (requires emulator)
    fetchDetects(flags, callback) {
        if (!this.emulator) return;

        this.runCommand(`${DIEInBrowser.DIE_BASE_COMMAND} -bj${flags} ${DIEInBrowser.SHARED_FILE_PATH}`, detects => {
            try {
                detects = JSON.parse(detects.slice(detects.indexOf("{")).trimStart());
            } catch (e) {
                detects = {
                    error: String(e),
                    raw: detects
                };
            }
            callback(detects);
        });
    }

    // Fetches file info (requires emulator)
    fetchInfo(callback) {
        if (!this.emulator) return;

        this.runCommand(`${DIEInBrowser.DIE_BASE_COMMAND} -ij ${DIEInBrowser.SHARED_FILE_PATH}`, info => {
            try {
                info = JSON.parse(info);
            } catch (e) {
                info = {
                    error: String(e),
                    raw: info
                };
            }
            callback(info);
        });
    }

    // Extracts strings from file without using 'strings' in emulator
    fetchStrings(callback) {
        const uint8 = this.fileBytes, results = [], minLength = 4;
        let currentString = "", startOffset = -1, stringsCount = 0;

        for (let i = 0; i < uint8.length; i++) {
            const c = uint8[i];
            const isTab = (c === 9);
            const isPrint = (c >= 32 && c <= 126);
            const isGraphic = isTab || isPrint;

            if (isGraphic) {
                if (startOffset === -1) {
                    startOffset = i;
                }
                currentString += String.fromCharCode(c);
            } else {
                if (currentString.length >= minLength) {
                    results.push({
                        offset: startOffset.toString(16),
                        str: currentString,
                        index: stringsCount++
                    });
                }
                currentString = "";
                startOffset = -1;
            }
        }

        if (currentString.length >= minLength) {
            results.push({
                offset: startOffset.toString(16),
                str: currentString,
                index: stringsCount++
            });
        }

        callback(results);
    }

    // Fetches file hashes (requires emulator)
    fetchHashes(callback) {
        if (!this.emulator) return;

        this.runCommand(`${DIEInBrowser.DIE_BASE_COMMAND} -j -S "Hash" ${DIEInBrowser.SHARED_FILE_PATH}`, hashes => {
            try {
                hashes = JSON.parse(hashes);
            } catch (e) {
                hashes = {
                    error: String(e),
                    raw: hashes
                };
            }
            callback(hashes);
        });
    }

    // Fetches file entropy (requires emulator)
    fetchEntropy(callback) {
        if (!this.emulator) return;

        this.runCommand(`${DIEInBrowser.DIE_BASE_COMMAND} -ej ${DIEInBrowser.SHARED_FILE_PATH}`, entropy => {
            try {
                entropy = JSON.parse(entropy);
            } catch (e) {
                entropy = {
                    error: String(e),
                    raw: entropy
                };
            }
            callback(entropy);
        });
    }
}
