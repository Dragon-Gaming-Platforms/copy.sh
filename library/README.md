# die.js

## Methods

### `constructor(config, startEmulator)`

Creates a new instance of `DIEInBrowser`.

Parameters:

- `config` - v86 configuration
- `startEmulator` - start the emulator or not

Example:

```js
const detectItEasy = window.DIE = new DIEInBrowser({
  wasm_path: "v86.wasm",
  bios: {
    url: "seabios.bin",
  },
  vga_bios: {
    url: "vgabios.bin",
  },
  initial_state: {
    url: "v86state.bin.zst",
  },
}, true);
```

### `runCommand(command, callback)`

Executes a shell command inside the **V86** emulator.

The command’s output (excluding the shell prompt) is passed to the callback once
execution completes.

Example:

```js
detectItEasy.runCommand("./run_diec.sh -v", console.log);
// Output: "die 3.10"
```

### `createFile(bytes)`

Uploads a file into the emulator.

- `bytes` - file content as a `Uint8Array`.

## Methods that require v86 emulator

### `fetchSections(callback)`

Fetches file sections, or returns null if there are none.

DIE command: `diec file.bin -j -S "IMAGE_SECTION_HEADER"`

### `fetchEntrypointPE(callback)`

Fetches PE file entrypoint, or returns null if file isn't PE.

DIE command: `diec file.bin -j -S "IMAGE_NT_HEADERS"`

### `fetchEntrypointELF(callback)`

Fetches ELF file entrypoint, or returns null if file isn't ELF.

DIE command: `diec file.bin -j -S "Elf_Ehdr"`

### `fetchDetects(flags, callback)`

Fetches file detects.

DIE command: `diec -bj${flags} file.bin`

### `fetchInfo(callback)`

Fetches file info.

DIE command: `diec -ij file.bin`

### `fetchHashes(callback)`

Fetches file hashes.

DIE command: `diec file.bin -j -S "Hash"`

### `fetchEntropy(callback)`

Fetches file entropy.

DIE command: `diec -ej file.bin`

## Methods that don't require v86 emulator

### `fetchStrings(callback)`

Extracts strings from file without using 'strings' in emulator.