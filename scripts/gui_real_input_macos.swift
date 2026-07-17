// gui_real_input_macos.swift — real OS-level mouse/keyboard driver for macOS e2e.
//
// Posts genuine CGEvents (the same event path a physical mouse/keyboard
// produces) at the HID event tap. This is required rather than
// `osascript`'s `tell application "System Events" to click at {x,y}` /
// `keystroke`: those AppleScript primitives do not reach the paranoid-gui
// window at all on this host. paranoid-gui is a winit-backed Slint window
// that exposes almost no NSAccessibility element tree (only titlebar
// chrome — close/zoom/minimize buttons and the title text are AX-visible;
// every LineEdit/Button/CheckBox inside the compiled `.slint` tree is not),
// so System Events GUI scripting has nothing to target inside the window
// and its synthetic events are silently dropped. Posting raw CGEvents at
// the HID tap bypasses the AX tree entirely and is delivered the same way
// a real mouse/keyboard input is, which paranoid-gui's winit event loop
// does receive and process.
//
// Requires the calling process (Terminal/iTerm/whatever invokes this
// binary) to hold Accessibility (and, on modern macOS, Input Monitoring)
// permission in System Settings > Privacy & Security. Compiled on demand
// with `swiftc` (part of the Xcode Command Line Tools already required for
// this repository's macOS builds) — no new package install.
//
// Subcommands:
//   click <x> <y>                 move + real left mouse down/up at the point
//   type <utf8-string>             posts one keyDown/keyUp per character via
//                                   CGEvent's Unicode string path (works for
//                                   any printable character without needing
//                                   a virtual-keycode table)
//   keyrepeat <keycode> <count> [cmd]
//                                   posts a virtual-keycode key event `count`
//                                   times in a row, optionally with the
//                                   Command modifier held throughout. Used to
//                                   reach the end of a LineEdit's text (Right
//                                   arrow, keycode 124) and then clear it
//                                   (Backspace, keycode 51) deterministically
//                                   regardless of the field's prior contents.

import CoreGraphics
import Foundation

func fail(_ message: String) -> Never {
    FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
    exit(64)
}

let args = CommandLine.arguments
guard args.count >= 2 else {
    fail("usage: gui_real_input_macos <click|type|keyrepeat> ...")
}

let source = CGEventSource(stateID: .hidSystemState)

switch args[1] {
case "click":
    guard args.count >= 4, let x = Double(args[2]), let y = Double(args[3]) else {
        fail("usage: gui_real_input_macos click <x> <y>")
    }
    let point = CGPoint(x: x, y: y)

    let moveEvent = CGEvent(mouseEventSource: source, mouseType: .mouseMoved, mouseCursorPosition: point, mouseButton: .left)
    moveEvent?.post(tap: .cghidEventTap)
    usleep(50_000)

    let downEvent = CGEvent(mouseEventSource: source, mouseType: .leftMouseDown, mouseCursorPosition: point, mouseButton: .left)
    downEvent?.post(tap: .cghidEventTap)
    usleep(50_000)

    let upEvent = CGEvent(mouseEventSource: source, mouseType: .leftMouseUp, mouseCursorPosition: point, mouseButton: .left)
    upEvent?.post(tap: .cghidEventTap)

case "type":
    guard args.count >= 3 else {
        fail("usage: gui_real_input_macos type <string>")
    }
    let text = args[2]
    for scalar in text.utf16 {
        let downEvent = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: true)
        downEvent?.keyboardSetUnicodeString(stringLength: 1, unicodeString: [scalar])
        downEvent?.post(tap: .cghidEventTap)
        usleep(15_000)

        let upEvent = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: false)
        upEvent?.keyboardSetUnicodeString(stringLength: 1, unicodeString: [scalar])
        upEvent?.post(tap: .cghidEventTap)
        usleep(15_000)
    }

case "keyrepeat":
    guard args.count >= 4, let keyCode = CGKeyCode(args[2]), let count = Int(args[3]) else {
        fail("usage: gui_real_input_macos keyrepeat <virtual-keycode> <count> [cmd]")
    }
    let useCommand = args.count >= 5 && args[4] == "cmd"
    // 30ms between each half of every key event. Posting CGEvents back to
    // back with only ~8ms of spacing was measured to intermittently drop
    // or coalesce individual key events under real system load on this
    // machine -- observed as a LineEdit's prior text only partially
    // clearing before new text was typed into it, corrupting the field
    // instead of failing loudly. 30ms per half-event (60ms per full
    // keystroke) was verified reliable across repeated clear-then-type
    // cycles against the real compiled paranoid-gui window; still fast
    // enough that clearing a field (250 events) costs well under the
    // per-stage timeout budget.
    for _ in 0..<count {
        let downEvent = CGEvent(keyboardEventSource: source, virtualKey: keyCode, keyDown: true)
        if useCommand { downEvent?.flags = .maskCommand }
        downEvent?.post(tap: .cghidEventTap)
        usleep(30_000)

        let upEvent = CGEvent(keyboardEventSource: source, virtualKey: keyCode, keyDown: false)
        if useCommand { upEvent?.flags = .maskCommand }
        upEvent?.post(tap: .cghidEventTap)
        usleep(30_000)
    }

default:
    fail("unknown subcommand: \(args[1]) (expected click|type|keyrepeat)")
}
