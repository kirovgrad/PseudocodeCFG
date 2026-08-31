# Pseudocode CFG for IDA Pro

Pseudocode CFG keeps IDA's native disassembly basic-block topology, but fills
each node with the Hex-Rays pseudocode lines mapped to that block.

<img width="1817" height="879" alt="Screenshot 2026-08-31 190410" src="https://github.com/user-attachments/assets/5625d675-d1d5-4848-9757-41626bd0778b" />

## Requirements

- IDA Pro 9.0 or newer (developed against the public IDAPython 9.x API)
- IDAPython
- A Hex-Rays decompiler for the input file's processor

## Installation

Copy `pseudocode_cfg.py` to your user plugin directory:

- Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
- Linux/macOS: `$HOME/.idapro/plugins/`

## Use

1. Put the cursor inside a function that Hex-Rays can decompile.
2. Press `Ctrl-Alt-G`, or choose **Edit > Plugins > Pseudocode CFG**.
3. Click an individual pseudocode line to synchronize its mapped disassembly
   address while keeping keyboard focus in the graph. Double-click to
   open/reuse a pseudocode view there.
4. Move the cursor in an address-synchronized disassembly or pseudocode view;
   the matching graph node and text row are selected.

Conditional edges use IDA's native convention: the taken/true path is green
and the fall-through/false path is red. Unconditional, switch, and ambiguous
edges retain the current IDA theme's default edge color.

Open pseudocode CFG functions and their plugin-specific block aliases and node
colors are stored in a private netnode inside the IDB. After the IDB is saved,
those graph windows are rebuilt automatically from the current decompilation
the next time the database opens. Closing a graph window before saving removes
it from the reopen list; its aliases and colors remain available if it is
opened again later.

The graph context menu also provides:

- **Refresh pseudocode CFG** (`Ctrl-R`) after changing types, names, or comments.
- **Open pseudocode at selected line** (`F5`).
- **Rename pseudocode block** (`N`) changes only the title shown in this
  pseudocode CFG. Enter an empty name to restore the IDA-derived title. The
  selected node text is updated in place without closing or rebuilding the
  graph, while all aliases and colors remain stored in the IDB.
- **Set node color** (`Ctrl-Shift-C`) and **Reset node color** affect only the
  pseudocode CFG. Both aliases and colors persist in the saved IDB.

## Mapping behavior

The plugin visits Hex-Rays ctree statements and expressions, asks
`cfunc_t.find_item_coords()` for each item's rendered pseudocode coordinate,
and assigns the item's address to the containing `ida_gdl.FlowChart` block.

Decompiler output is not a one-to-one translation of machine instructions:

- One pseudocode line can contain items from multiple basic blocks. Such a line
  is intentionally repeated in every relevant node.
- Braces, the function declaration, and some declarations have no address.
  Prefix lines go in the entry block; other structural lines follow the nearest
  address-bearing pseudocode line.
- A block optimized away by Hex-Rays remains visible with a short placeholder.
- Prologue/epilogue instructions can have no distinct pseudocode line because
  they implement calling-convention mechanics rather than source operations.
- Ctree items without a rendered line coordinate are ignored; this is normal
  for optimized-away and helper items and does not prevent graph creation.

These rules preserve the native CFG even when the structured ctree and machine
CFG do not have identical shapes.

## Troubleshooting

- **Nothing happens:** check IDA's Output window for a load error and confirm
  the file is directly inside the active `plugins` directory.
- **Decompiler unavailable:** install/activate the Hex-Rays decompiler matching
  the file's processor.
- **Shortcut conflict:** invoke the plugin from **Edit > Plugins**, or change
  `wanted_hotkey` near the end of `pseudocode_cfg.py`.
- **Stale graph text:** use **Refresh pseudocode CFG**.
- **A graph does not reopen:** save the IDB while its pseudocode CFG window is
  still open. Graphs that cannot currently be decompiled remain in the reopen
  list and will be retried the next time the IDB opens.

## License

MIT. See `LICENSE`.
