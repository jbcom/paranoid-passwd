/**
 * wasm_entry.c — WASI linker stub
 *
 * Zig's WASI libc links __main_void.o which references main().
 * Since paranoid.wasm is a reactor (library), not a command, we provide
 * a stub main() to satisfy the linker. This function is never called
 * at runtime — all entry points are the exported functions in paranoid.c.
 *
 * See: https://github.com/ziglang/zig/issues/22570
 */

int main(void) {
    return 0;
}
