""" Pseudocode CFG: render Hex-Rays pseudocode in IDA basic blocks.
"""

from __future__ import annotations

from collections import defaultdict
import json
import zlib

import ida_funcs
import ida_gdl
import ida_graph
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_netnode


PLUGIN_NAME = "Pseudocode CFG"
PLUGIN_VERSION = "1.5.0"
DEFAULT_COLOR = 0xFFFFFFFF
STATE_NETNODE_NAME = "$ Pseudocode CFG state"
STATE_BLOB_INDEX = 0
STATE_BLOB_TAG = "P"
TRUE_EDGE_COLOR = 0x008000
FALSE_EDGE_COLOR = 0x0000FF


def _format_ea(ea):
    width = 16 if ida_idaapi.BADADDR > 0xFFFFFFFF else 8
    return "0x%0*X" % (width, ea)


def _tagged_line(simple_line):
    return str(getattr(simple_line, "line", simple_line)).rstrip("\r\n")


def _ea_key(ea):
    return "%X" % int(ea)


class PseudocodeCFGState:
    def __init__(self):
        self._data = {
            "version": 1,
            "open_functions": [],
            "functions": {},
        }
        self._node = None
        try:
            self._node = ida_netnode.netnode(
                STATE_NETNODE_NAME, 0, True
            )
            raw = self._node.getblob(STATE_BLOB_INDEX, STATE_BLOB_TAG)
            if raw:
                loaded = json.loads(zlib.decompress(raw).decode("utf-8"))
                if (
                    isinstance(loaded, dict)
                    and loaded.get("version") == 1
                    and isinstance(loaded.get("open_functions"), list)
                    and isinstance(loaded.get("functions"), dict)
                ):
                    self._data = loaded
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError,
                zlib.error) as error:
            print("%s: could not load saved state: %s" % (
                PLUGIN_NAME, error
            ))

    def _save(self):
        if self._node is None:
            return False
        try:
            payload = json.dumps(
                self._data, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
            result = self._node.setblob(
                zlib.compress(payload), STATE_BLOB_INDEX, STATE_BLOB_TAG
            )
            if result is False:
                raise RuntimeError("netnode rejected the state blob")
            return True
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
            print("%s: could not save state: %s" % (PLUGIN_NAME, error))
            return False

    def _function(self, func_ea, create=False):
        functions = self._data["functions"]
        key = _ea_key(func_ea)
        function = functions.get(key)
        if not isinstance(function, dict):
            if not create:
                return {}
            function = {"aliases": {}, "colors": {}}
            functions[key] = function
        function.setdefault("aliases", {})
        function.setdefault("colors", {})
        return function

    def open_functions(self):
        result = []
        for value in self._data["open_functions"]:
            try:
                result.append(int(value, 16))
            except (TypeError, ValueError):
                continue
        return tuple(sorted(set(result)))

    def set_open_functions(self, addresses):
        self._data["open_functions"] = sorted({
            _ea_key(ea) for ea in addresses
        })
        return self._save()

    def mark_open(self, func_ea):
        addresses = set(self.open_functions())
        addresses.add(func_ea)
        return self.set_open_functions(addresses)

    def mark_closed(self, func_ea):
        addresses = set(self.open_functions())
        addresses.discard(func_ea)
        return self.set_open_functions(addresses)

    def aliases_for(self, func_ea):
        result = {}
        aliases = self._function(func_ea).get("aliases", {})
        if not isinstance(aliases, dict):
            return result
        for ea, alias in aliases.items():
            try:
                if isinstance(alias, str) and alias:
                    result[int(ea, 16)] = alias
            except (TypeError, ValueError):
                continue
        return result

    def set_alias(self, func_ea, block_ea, alias):
        aliases = self._function(func_ea, create=True)["aliases"]
        key = _ea_key(block_ea)
        if alias:
            aliases[key] = alias
        else:
            aliases.pop(key, None)
        return self._save()

    def colors_for(self, func_ea):
        result = {}
        colors = self._function(func_ea).get("colors", {})
        if not isinstance(colors, dict):
            return result
        for ea, color in colors.items():
            try:
                result[int(ea, 16)] = int(color)
            except (TypeError, ValueError):
                continue
        return result

    def set_color(self, func_ea, block_ea, color):
        colors = self._function(func_ea, create=True)["colors"]
        colors[_ea_key(block_ea)] = int(color)
        return self._save()


class BlockRecord:
    def __init__(self, block_id, start_ea, end_ea, successor_ids):
        self.id = block_id
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.successor_ids = tuple(successor_ids)

    def contains(self, ea):
        return self.start_ea <= ea < self.end_ea


class PseudocodeLine:
    def __init__(self, source_line, tagged_text, plain_text, addresses):
        self.source_line = source_line
        self.tagged_text = tagged_text
        self.plain_text = plain_text
        self.addresses = tuple(sorted(set(addresses)))

    def address_for_block(self, block):
        for ea in self.addresses:
            if block.contains(ea):
                return ea
        return block.start_ea


class NodeRecord:
    def __init__(self, block, title, lines, block_name=None):
        self.block = block
        self.title = title
        self.lines = tuple(lines)
        self.block_name = (
            block_name
            if block_name is not None
            else ida_lines.tag_remove(title).split("  [", 1)[0]
        )

    def title_for_name(self, block_name):
        title_text = "%s" % (
            block_name,
        )
        return ida_lines.COLSTR(title_text, ida_lines.SCOLOR_LOCNAME)

    def text(self, title=None):
        if self.lines:
            body = [line.tagged_text for line in self.lines]
        else:
            body = [ida_lines.COLSTR(
                "  /* no direct pseudocode (optimized or synthetic block) */",
                ida_lines.SCOLOR_AUTOCMT,
            )]
        return "\n".join([self.title if title is None else title] + body)

    def row_for_ea(self, ea):
        if not self.lines:
            return 1

        exact_rows = []
        candidates = []
        for index, line in enumerate(self.lines, 1):
            in_block = [address for address in line.addresses
                        if self.block.contains(address)]
            if ea in in_block:
                exact_rows.append(index)
            for address in in_block:
                candidates.append((abs(address - ea), index))

        if exact_rows:
            return exact_rows[0]
        if candidates:
            return min(candidates)[1]
        return 1

    def ea_for_row(self, row):
        if row <= 0 or not self.lines:
            return self.block.start_ea
        index = min(row - 1, len(self.lines) - 1)
        return self.lines[index].address_for_block(self.block)


class _NodeColorForm(ida_kernwin.Form):
    def __init__(self, initial_color):
        ida_kernwin.Form.__init__(self, r"""BUTTON YES* Apply
BUTTON CANCEL Cancel
Node color

<Choose the node background color:{color}>
""", {
            "color": ida_kernwin.Form.ColorInput(value=initial_color),
        })


def _choose_node_color(initial_color):
    if initial_color == DEFAULT_COLOR:
        initial_color = 0xFFFFFF
    form = _NodeColorForm(initial_color)
    form.Compile()
    try:
        if form.Execute() != 1:
            return None
        return form.color.value
    finally:
        form.Free()


class _CtreeCoordinateCollector(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.addresses_by_line = defaultdict(set)

    def _record(self, item):
        try:
            ea = int(getattr(item, "ea", ida_idaapi.BADADDR))
        except (TypeError, ValueError):
            return
        if ea == ida_idaapi.BADADDR:
            return
        try:
            coords = self.cfunc.find_item_coords(item)
            if not coords:
                return
            _x, y = coords
            y = int(y)
        except (RuntimeError, TypeError, ValueError):
            return
        if y < 0:
            return
        self.addresses_by_line[y].add(ea)

    def visit_insn(self, instruction):
        self._record(instruction)
        return 0

    def visit_expr(self, expression):
        self._record(expression)
        return 0


class PseudocodeCFGModel:
    def __init__(self, func_ea, function_name, blocks, nodes):
        self.func_ea = func_ea
        self.function_name = function_name
        self.blocks = tuple(blocks)
        self.nodes = tuple(nodes)
        self.block_by_id = {block.id: block for block in self.blocks}
        self.node_by_block_id = {node.block.id: node for node in self.nodes}

    def block_containing(self, ea):
        for block in self.blocks:
            if block.contains(ea):
                return block
        return None

    def conditional_edge_colors(self, block):
        if len(block.successor_ids) != 2:
            return {}
        fallthrough_ids = [
            successor_id
            for successor_id in block.successor_ids
            if (
                successor_id in self.block_by_id
                and self.block_by_id[successor_id].start_ea == block.end_ea
            )
        ]
        if len(fallthrough_ids) != 1:
            return {}
        false_successor_id = fallthrough_ids[0]
        true_successor_ids = [
            successor_id
            for successor_id in block.successor_ids
            if successor_id != false_successor_id
        ]
        if len(true_successor_ids) != 1:
            return {}
        return {
            false_successor_id: FALSE_EDGE_COLOR,
            true_successor_ids[0]: TRUE_EDGE_COLOR,
        }


class PseudocodeCFGBuilder:
    def __init__(self, func_ea):
        self.func_ea = func_ea

    def build(self):
        function = ida_funcs.get_func(self.func_ea)
        if function is None:
            raise RuntimeError("The address is not inside a function")

        cfunc = ida_hexrays.decompile(function.start_ea)
        if cfunc is None:
            raise RuntimeError("Hex-Rays could not decompile this function")

        blocks = self._build_blocks(function)
        if not blocks:
            raise RuntimeError("IDA did not produce a flow chart for this function")

        pseudocode = list(cfunc.get_pseudocode())
        addresses_by_line = self._collect_coordinates(cfunc)
        block_ids_by_line, addresses_by_line_and_block = self._map_lines_to_blocks(
            blocks, addresses_by_line
        )
        self._place_synthetic_lines(
            pseudocode, blocks, block_ids_by_line, addresses_by_line_and_block
        )

        lines_by_block = defaultdict(list)
        for line_number, simple_line in enumerate(pseudocode):
            tagged = _tagged_line(simple_line)
            plain = ida_lines.tag_remove(tagged).rstrip()
            if not plain.strip():
                continue
            for block_id in sorted(block_ids_by_line.get(line_number, ())):
                addresses = addresses_by_line_and_block[line_number].get(
                    block_id, ()
                )
                lines_by_block[block_id].append(PseudocodeLine(
                    line_number, plain, plain, addresses
                ))

        function_name = ida_name.get_ea_name(function.start_ea)
        if not function_name:
            function_name = "sub_%X" % function.start_ea
        nodes = []
        for block in blocks:
            block_name = ida_name.get_ea_name(block.start_ea)
            if not block_name:
                block_name = (
                    function_name if block.start_ea == function.start_ea
                    else "block_%X" % block.start_ea
                )
            title_text = "%s" % (
                block_name,
            )
            title = ida_lines.COLSTR(title_text, ida_lines.SCOLOR_LOCNAME)
            nodes.append(NodeRecord(
                block, title, lines_by_block[block.id], block_name
            ))

        return PseudocodeCFGModel(function.start_ea, function_name, blocks, nodes)

    @staticmethod
    def _build_blocks(function):
        flow_chart = ida_gdl.FlowChart(function, flags=ida_gdl.FC_PREDS)
        blocks = []
        for block in flow_chart:
            blocks.append(BlockRecord(
                block.id,
                block.start_ea,
                block.end_ea,
                [successor.id for successor in block.succs()],
            ))
        return blocks

    @staticmethod
    def _collect_coordinates(cfunc):
        collector = _CtreeCoordinateCollector(cfunc)
        collector.apply_to(cfunc.body, None)
        return collector.addresses_by_line

    @staticmethod
    def _map_lines_to_blocks(blocks, addresses_by_line):
        block_ids_by_line = defaultdict(set)
        addresses_by_line_and_block = defaultdict(lambda: defaultdict(set))
        for line_number, addresses in addresses_by_line.items():
            for ea in addresses:
                for block in blocks:
                    if block.contains(ea):
                        block_ids_by_line[line_number].add(block.id)
                        addresses_by_line_and_block[line_number][block.id].add(ea)
                        break
        return block_ids_by_line, addresses_by_line_and_block

    @staticmethod
    def _place_synthetic_lines(pseudocode, blocks, block_ids_by_line,
                               addresses_by_line_and_block):
        mapped_lines = sorted(block_ids_by_line)
        entry_block = blocks[0]

        for line_number, simple_line in enumerate(pseudocode):
            if line_number in block_ids_by_line:
                continue
            tagged = _tagged_line(simple_line)
            if not ida_lines.tag_remove(tagged).strip():
                continue

            if not mapped_lines or line_number < mapped_lines[0]:
                owner_ids = {entry_block.id}
            else:
                nearest = min(
                    mapped_lines,
                    key=lambda mapped: (abs(mapped - line_number),
                                        mapped > line_number, mapped),
                )
                owner_ids = set(block_ids_by_line[nearest])

            block_ids_by_line[line_number].update(owner_ids)
            for block_id in owner_ids:
                block = next(block for block in blocks if block.id == block_id)
                addresses_by_line_and_block[line_number][block_id].add(
                    block.start_ea
                )


class PseudocodeCFGViewer(ida_graph.GraphViewer):
    def __init__(self, controller, model):
        title = "%s: %s" % (
            PLUGIN_NAME, model.function_name
        )
        ida_graph.GraphViewer.__init__(self, title, close_open=False)
        self.controller = controller
        self.model = model
        self.block_to_graph_node = {}
        self.graph_node_to_record = {}
        self.edge_colors = {}
        self.state = getattr(controller, "state", None)
        if self.state is None:
            self.block_aliases = {}
            self.block_colors = {}
        else:
            self.block_aliases = self.state.aliases_for(model.func_ea)
            self.block_colors = self.state.colors_for(model.func_ea)
        self.selected_ea = model.func_ea
        self.selected_graph_node = None
        self._commands_added = False
        self._syncing = False
        self._refresh_requested = False
        self._pending_sync_ea = None

    def _graph_viewer_handle(self):
        widget = self.GetWidget()
        if widget is None:
            return None
        return ida_graph.get_graph_viewer(widget)

    # Refresh plumbing
    
    def request_refresh(self, sync_ea=None):
        """Schedule exactly one GraphViewer.Refresh() outside any callback.
        """
        if sync_ea is not None:
            self._pending_sync_ea = sync_ea
        if self._refresh_requested:
            return
        self._refresh_requested = True

        def do_refresh():
            self._refresh_requested = False
            try:
                self.Refresh()
            except (AttributeError, RuntimeError, TypeError):
                pass
            return False

        def do_sync():
            ea = self._pending_sync_ea
            self._pending_sync_ea = None
            if ea is not None:
                self.sync_to_ea(ea)
            return False

        try:
            ida_kernwin.execute_ui_requests([do_refresh, do_sync])
        except (AttributeError, RuntimeError, TypeError, ValueError) as error:
            self._refresh_requested = False
            print("%s: could not schedule a refresh: %s" % (
                PLUGIN_NAME, error
            ))

    def OnRefresh(self):
        self.Clear()
        self.block_to_graph_node.clear()
        self.graph_node_to_record.clear()
        self.edge_colors.clear()

        for node_record in self.model.nodes:
            graph_node = self.AddNode(node_record)
            self.block_to_graph_node[node_record.block.id] = graph_node
            self.graph_node_to_record[graph_node] = node_record

        for block in self.model.blocks:
            source = self.block_to_graph_node.get(block.id)
            if source is None:
                continue
            conditional_colors = self.model.conditional_edge_colors(block)
            for successor_id in block.successor_ids:
                destination = self.block_to_graph_node.get(successor_id)
                if destination is not None:
                    self.AddEdge(source, destination)
                    color = conditional_colors.get(successor_id)
                    if color is not None:
                        self.edge_colors[(source, destination)] = color

        if self.edge_colors:
            try:
                ida_kernwin.execute_ui_requests([self._apply_edge_colors])
            except (AttributeError, RuntimeError, TypeError, ValueError):
                # Edge colors are cosmetic and must not prevent graph creation.
                pass
        return True

    def _apply_edge_colors(self):
        try:
            viewer = self._graph_viewer_handle()
            if viewer is None:
                return False
            graph = ida_graph.get_viewer_graph(viewer)
            if graph is None:
                return False
            for (source, destination), color in self.edge_colors.items():
                edge = ida_graph.edge_t(source, destination)
                info = graph.get_edge(edge)
                if info is None:
                    info = ida_graph.edge_info_t()
                info.color = color
                graph.set_edge(edge, info)
        except (AttributeError, RuntimeError, TypeError, ValueError) as error:
            print("%s: could not apply edge colors: %s" % (
                PLUGIN_NAME, error
            ))
        return False

    # Node rendering
    
    def OnGetText(self, node_id):
        node = self[node_id]
        return (node.text(self._display_title(node)), self._node_bgcolor(node))

    def _node_bgcolor(self, node):
        ea = node.block.start_ea
        color = self.block_colors.get(ea)
        if color is None:
            color = ida_nalt.get_item_color(ea)
        try:
            return int(color)
        except (TypeError, ValueError):
            return DEFAULT_COLOR

    def _display_title(self, node):
        alias = self.block_aliases.get(node.block.start_ea)
        if alias is None:
            return node.title
        return node.title_for_name(alias)

    def OnHint(self, node_id):
        node = self[node_id]
        return "%s\n%d pseudocode line(s)" % (
            ida_lines.tag_remove(self._display_title(node)), len(node.lines)
        )

    def Show(self):
        if not ida_graph.GraphViewer.Show(self):
            return False
        if not self._commands_added:
            self.cmd_refresh = self.AddCommand("Refresh pseudocode CFG", "Ctrl+R")
            self.cmd_pseudocode = self.AddCommand(
                "Open pseudocode at selected line", "F5"
            )
            self.cmd_rename = self.AddCommand(
                "Rename pseudocode block...", "N"
            )
            self.cmd_color = self.AddCommand(
                "Set node color...", "Ctrl+Shift+C"
            )
            self.cmd_reset_color = self.AddCommand("Reset node color", "")
            self._commands_added = True
        return True

    def OnCommand(self, command_id):
        if command_id == self.cmd_refresh:
            self.refresh_model()
        elif command_id == self.cmd_pseudocode:
            self.open_selected_pseudocode()
        elif command_id == self.cmd_rename:
            self.rename_selected_block()
        elif command_id == self.cmd_color:
            self.set_selected_node_color()
        elif command_id == self.cmd_reset_color:
            self.reset_selected_node_color()

    @staticmethod
    def _event_position(event):
        try:
            node_id = int(event.renderer_pos.node)
            row = int(event.renderer_pos.cy)
        except (AttributeError, TypeError, ValueError):
            return None
        if node_id < 0:
            return None
        return node_id, row

    def _select_event_line(self, event):
        position = self._event_position(event)
        if position is None:
            return None
        node_id, row = position
        node = self.graph_node_to_record.get(node_id)
        if node is None:
            return None
        self.selected_graph_node = node_id
        self.selected_ea = node.ea_for_row(row)
        return self.selected_ea

    def view_click(self, view, event):
        ida_graph.GraphViewer.view_click(self, view, event)
        ea = self._select_event_line(event)
        if ea is not None:
            flags = ida_kernwin.UIJMP_IDAVIEW | ida_kernwin.UIJMP_DONTPUSH
            ida_kernwin.jumpto(ea, -1, flags)

    def view_dblclick(self, view, event):
        ida_graph.GraphViewer.view_dblclick(self, view, event)
        if self._select_event_line(event) is not None:
            self.open_selected_pseudocode()

    def view_close(self, view, *args):
        try:
            ida_graph.GraphViewer.view_close(self, view, *args)
        finally:
            self.controller.viewer_closed(self)

    def open_selected_pseudocode(self):
        ida_hexrays.open_pseudocode(self.selected_ea, ida_hexrays.OPF_REUSE)

    def _selected_node_record(self):
        try:
            viewer = self._graph_viewer_handle()
            current = (
                -1
                if viewer is None
                else ida_graph.viewer_get_curnode(viewer)
            )
        except (AttributeError, RuntimeError, TypeError):
            current = -1
        if current in self.graph_node_to_record:
            self.selected_graph_node = current

        node = self.graph_node_to_record.get(self.selected_graph_node)
        if node is not None:
            return node
        block = self.model.block_containing(self.selected_ea)
        if block is None:
            return None
        self.selected_graph_node = self.block_to_graph_node.get(block.id)
        return self.model.node_by_block_id.get(block.id)

    # Commands
    
    def rename_selected_block(self):
        node = self._selected_node_record()
        if node is None:
            return
        ea = node.block.start_ea
        current_name = self.block_aliases.get(ea, node.block_name)
        new_name = ida_kernwin.ask_str(
            current_name,
            ida_kernwin.HIST_IDENT,
            "Rename pseudocode CFG block at %s (empty resets)" % _format_ea(ea),
        )
        if new_name is None:
            return
        new_name = new_name.strip()
        if not new_name or new_name == node.block_name:
            self.block_aliases.pop(ea, None)
            alias = None
        else:
            self.block_aliases[ea] = new_name
            alias = new_name
        if self.state is not None:
            self.state.set_alias(self.model.func_ea, ea, alias)
        self.selected_ea = ea
        self.request_refresh()

    def set_selected_node_color(self):
        node = self._selected_node_record()
        if node is None:
            return
        ea = node.block.start_ea
        if ea in self.block_colors:
            initial_color = self.block_colors[ea]
        else:
            initial_color = ida_nalt.get_item_color(ea)
        color = _choose_node_color(initial_color)
        if color is None:
            return
        self.block_colors[ea] = color
        if self.state is not None:
            self.state.set_color(self.model.func_ea, ea, color)
        self.request_refresh()

    def reset_selected_node_color(self):
        node = self._selected_node_record()
        if node is None:
            return
        ea = node.block.start_ea
        self.block_colors[ea] = DEFAULT_COLOR
        if self.state is not None:
            self.state.set_color(self.model.func_ea, ea, DEFAULT_COLOR)
        self.request_refresh()

    def refresh_model(self):
        try:
            self.model = PseudocodeCFGBuilder(self.model.func_ea).build()
        except Exception as error:
            ida_kernwin.warning("%s refresh failed:\n%s" % (
                PLUGIN_NAME, error
            ))
            return
        self.request_refresh(sync_ea=self.selected_ea)

    def sync_to_ea(self, ea):
        if self._syncing:
            return
        block = self.model.block_containing(ea)
        if block is None:
            return
        node_id = self.block_to_graph_node.get(block.id)
        node = self.model.node_by_block_id.get(block.id)
        widget = self.GetWidget()
        if node_id is None or node is None or widget is None:
            return

        row = node.row_for_ea(ea)
        self.selected_ea = ea
        self.selected_graph_node = node_id
        self._syncing = True
        try:
            self.Select(node_id)
            place = ida_graph.create_user_graph_place(node_id, row)
            ida_kernwin.jumpto(widget, place, 0, row)
        except (RuntimeError, TypeError):
            pass
        finally:
            self._syncing = False


class _NavigationHooks(ida_kernwin.UI_Hooks):
    def __init__(self, controller):
        ida_kernwin.UI_Hooks.__init__(self)
        self.controller = controller

    def screen_ea_changed(self, ea, previous_ea):
        self.controller.screen_ea_changed(ea)

    def ready_to_run(self):
        self.controller.restore_saved_viewers()

    def saving(self):
        self.controller.save_open_viewers()

    def term(self):
        self.controller.shutting_down = True


class PseudocodeCFGController:
    def __init__(self):
        self.viewers = {}
        self.state = PseudocodeCFGState()
        self.shutting_down = False
        self._restore_started = False
        self.hooks = _NavigationHooks(self)
        self.hooks.hook()

    def close(self):
        self.shutting_down = True
        self.save_open_viewers()
        self.hooks.unhook()
        for viewer in list(self.viewers.values()):
            try:
                viewer.Close()
            except RuntimeError:
                pass
        self.viewers.clear()

    def show_for_ea(self, ea):
        function = ida_funcs.get_func(ea)
        if function is None:
            ida_kernwin.warning("Place the cursor inside a function first.")
            return

        existing = self.viewers.get(function.start_ea)
        if existing is not None:
            self.state.mark_open(function.start_ea)
            existing.Show()
            existing.sync_to_ea(ea)
            return

        try:
            model = PseudocodeCFGBuilder(function.start_ea).build()
        except Exception as error:
            ida_kernwin.warning("%s could not build the graph:\n%s" % (
                PLUGIN_NAME, error
            ))
            return

        viewer = PseudocodeCFGViewer(self, model)
        self.viewers[function.start_ea] = viewer
        if not viewer.Show():
            self.viewers.pop(function.start_ea, None)
            ida_kernwin.warning("IDA could not create the pseudocode graph view.")
            return
        self.state.mark_open(function.start_ea)
        viewer.sync_to_ea(ea)

    def restore_saved_viewers(self):
        if self._restore_started:
            return
        self._restore_started = True
        requests = []
        for func_ea in self.state.open_functions():
            def restore_one(ea=func_ea):
                if ida_funcs.get_func(ea) is None:
                    self.state.mark_closed(ea)
                else:
                    self.show_for_ea(ea)
                return False

            requests.append(restore_one)
        if not requests:
            return
        try:
            ida_kernwin.execute_ui_requests(requests)
        except (AttributeError, RuntimeError, TypeError, ValueError) as error:
            print("%s: could not restore saved graphs: %s" % (
                PLUGIN_NAME, error
            ))

    def save_open_viewers(self):
        self.state.set_open_functions(self.viewers)

    def screen_ea_changed(self, ea):
        for viewer in list(self.viewers.values()):
            viewer.sync_to_ea(ea)

    def viewer_closed(self, viewer):
        current = self.viewers.get(viewer.model.func_ea)
        if current is viewer:
            self.viewers.pop(viewer.model.func_ea, None)
            if not self.shutting_down:
                self.state.mark_closed(viewer.model.func_ea)


class PseudocodeCFGPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC
    comment = "Render Hex-Rays pseudocode in the native assembly CFG"
    help = "Open a basic-block graph populated with mapped pseudocode lines."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Ctrl-Alt-G"

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            return ida_idaapi.PLUGIN_SKIP
        self.controller = PseudocodeCFGController()
        print("%s %s loaded (Ctrl-Alt-G)" % (PLUGIN_NAME, PLUGIN_VERSION))
        return ida_idaapi.PLUGIN_KEEP

    def run(self, argument):
        self.controller.restore_saved_viewers()
        self.controller.show_for_ea(ida_kernwin.get_screen_ea())

    def term(self):
        if hasattr(self, "controller"):
            self.controller.close()


def PLUGIN_ENTRY():
    return PseudocodeCFGPlugin()
