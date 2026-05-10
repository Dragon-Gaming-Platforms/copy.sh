class DIEInBrowser {
    static SHARED_FILE_NAME = "file.bin";
    static DIE_BASE_COMMAND = "./run_diec.sh";

    constructor(config) {
        // Creating emulator
        this.emulator = window.emulator = new V86({
            memory_size: 512 * 1024 * 1024,
            vga_memory_size: 8 * 1024 * 1024,
            autostart: true,
            filesystem: {},
            disable_keyboard: true,
            disable_mouse: true,
            ...config
        });
    }

    runCommand(command, callback) {
        // Sending command
        emulator.serial0_send(command + "\n");

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

    createFileAndAnalyze(bytes, flags, callback) {
        const sharedName = DIEInBrowser.SHARED_FILE_NAME;
        this.emulator.create_file(sharedName, bytes).then(() => {
            this.analyzeFile(`/mnt/${sharedName}`, flags, callback);
        });
    }

    analyzeAdditionalInfo(path, callback) {
        // We'll be iterating over this array to find suitable methods
        const methodsArr = ["IMAGE_SECTION_HEADER", "IMAGE_NT_HEADERS", "Elf_Ehdr"];
        const callbackTypes = ["sections", "entrypointPE", "entrypointELF"];

        const methodProcessCallback = () => {
            if (methodsArr.length != 0) {
                const methodName = methodsArr.shift();
                const callbackType = callbackTypes.shift();

                this.runCommand(`${DIEInBrowser.DIE_BASE_COMMAND} ${path} -j -S "${methodName}"`, methodOutput => {
                    try {
                        methodOutput = JSON.parse(methodOutput.slice(methodOutput.indexOf("{")).trimStart());
                        methodOutput = methodOutput?.data;

                        if (methodOutput) {
                            switch (methodName) {
                                // Entry point (PE)
                                case "IMAGE_NT_HEADERS": {
                                    let baseAddress = "", entrypoint = "";
                                    if (methodOutput?.IMAGE_NT_HEADERS?.IMAGE_OPTIONAL_HEADER?.AddressOfEntryPoint) {
                                        entrypoint = methodOutput.IMAGE_NT_HEADERS.IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint;
                                    }
                                    if (methodOutput?.IMAGE_NT_HEADERS?.IMAGE_OPTIONAL_HEADER?.ImageBase) {
                                        baseAddress = methodOutput.IMAGE_NT_HEADERS.IMAGE_OPTIONAL_HEADER.ImageBase;
                                    }
                                    callback(callbackType, {
                                        "Base address": baseAddress,
                                        "Entry point": entrypoint
                                    });
                                    break;
                                }

                                // Sections (PE)
                                case "IMAGE_SECTION_HEADER": {
                                    callback(callbackType, methodOutput);
                                    break;
                                }

                                // Entry point (ELF)
                                case "Elf_Ehdr": {
                                    if (methodOutput?.Elf_Ehdr?.entry) {
                                        callback(callbackType, {
                                            "Entry point": methodOutput.Elf_Ehdr.entry
                                        });
                                    }
                                    break;
                                }

                                default:
                                    break;
                            }
                        } else {
                            callback(callbackType, null);
                        }
                    } catch (e) {
                        callback(callbackType, {
                            error: String(e),
                            raw: methodOutput
                        });
                    };

                    methodProcessCallback();
                });
            }
        };

        methodProcessCallback();
    }

    analyzeFile(path, flags, callback) {
        // Detects
        this.runCommand(`${DIEInBrowser.DIE_BASE_COMMAND} -bj${flags} ${path}`, detects => {
            try {
                detects = JSON.parse(detects.slice(detects.indexOf("{")).trimStart());
            } catch (e) {
                detects = {
                    error: String(e),
                    raw: detects
                };
            }
            callback("detects", detects);

            // Info
            this.runCommand(`${DIEInBrowser.DIE_BASE_COMMAND} -ij ${path}`, info => {
                try {
                    info = JSON.parse(info);
                } catch (e) {
                    info = {
                        error: String(e),
                        raw: info
                    };
                }
                callback("info", info);

                // Hashes
                this.runCommand(`${DIEInBrowser.DIE_BASE_COMMAND} -j -S "Hash" ${path}`, hashes => {
                    try {
                        hashes = JSON.parse(hashes);
                    } catch (e) {
                        hashes = {
                            error: String(e),
                            raw: hashes
                        };
                    }
                    callback("hashes", hashes);

                    // Entropy
                    this.runCommand(`${DIEInBrowser.DIE_BASE_COMMAND} -j -S "Entropy" ${path}`, entropy => {
                        try {
                            entropy = JSON.parse(entropy);
                        } catch (e) {
                            entropy = {
                                error: String(e),
                                raw: entropy
                            };
                        }
                        callback("entropy", entropy);

                        // Strings
                        this.runCommand(`strings -t x ${path} | base64`, strings => {
                            callback("strings", atob(strings))

                            // Analyze additional info in the file
                            this.analyzeAdditionalInfo(path, callback);
                        });
                    });
                });
            });
        });
    }
}
