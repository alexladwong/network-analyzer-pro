#!/usr/bin/env python3
"""Programmatic analysis of main.py for refactoring — generates refactor_report.json + .md"""

import ast
import json
import os
import sys
from pathlib import Path
from collections import defaultdict

REPO = Path(__file__).resolve().parent.parent
MAIN = REPO / "main.py"

###############################################################################
# 1. Parse
###############################################################################
with open(MAIN, encoding="utf-8") as f:
    source = f.read()
tree = ast.parse(source, filename="main.py")

lines = source.split("\n")
total_lines = len(lines)

###############################################################################
# 2. Helpers
###############################################################################
def node_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node_name(node.value) + "." + node.attr
    if isinstance(node, ast.Subscript):
        return node_name(node.value) + "[...]"
    if isinstance(node, ast.Call):
        return node_name(node.func) + "(...)"
    return "?"

class SymbolVisitor(ast.NodeVisitor):
    def __init__(self):
        self.symbols = []
        self._current_class = None
    
    def _record(self, name, typ, node, deps=None):
        deps = deps or []
        self.symbols.append(dict(
            name=name,
            type=typ,
            line=node.lineno,
            end=getattr(node, 'end_lineno', node.lineno),
            deps=deps,
        ))
    
    def visit_Import(self, node):
        for alias in node.names:
            self._record(alias.name, "import", node)
    
    def visit_ImportFrom(self, node):
        module = node.module or ""
        for alias in node.names:
            full = f"{module}.{alias.name}" if module else alias.name
            self._record(full, "import_from", node)
    
    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._record(target.id, "global_assign", node)
    
    def visit_ClassDef(self, node):
        bases = [node_name(b) for b in node.bases]
        self._current_class = node.name
        self._record(node.name, "class", node, deps=bases)
        self.generic_visit(node)
        self._current_class = None
    
    def visit_FunctionDef(self, node):
        parent = self._current_class
        full = f"{parent}.{node.name}" if parent else node.name
        typ = "method" if parent else "function"
        self._record(full, typ, node)
        self.generic_visit(node)

visitor = SymbolVisitor()
visitor.visit(tree)
symbols = visitor.symbols

###############################################################################
# 3. Dependency analysis
###############################################################################
# Find all function/method definitions
func_map = {}
for s in symbols:
    if s['type'] in ('function', 'method'):
        func_map[s['name']] = s

# Build call graph
caller_to_callees = defaultdict(set)  # caller -> set of names called
callee_to_callers = defaultdict(set)  # callee -> set of callers

for s in symbols:
    if s['type'] not in ('function', 'method'):
        continue
    name = s['name']
    node = None
    # Re-find the AST node
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # For methods, check parent class context
            fn_name = n.name
            caller_name = fn_name
            for parent_node in ast.walk(tree):
                if isinstance(parent_node, ast.ClassDef):
                    for child in parent_node.body:
                        if child is n:
                            caller_name = f"{parent_node.name}.{fn_name}"
                            break
            if caller_name == name:
                node = n
                break
    
    if node is None:
        continue
    
    # Find calls in this function
    for call_node in ast.walk(node):
        if isinstance(call_node, ast.Call):
            callee = node_name(call_node.func)
            if callee and callee != name:
                # Extract base name
                callee_short = callee.split(".")[-1] if "." in callee else callee
                caller_to_callees[name].add(callee_short)
                callee_to_callers[callee_short].add(name)

###############################################################################
# 4. Inventory by category
###############################################################################
imports = [s for s in symbols if s['type'].startswith('import')]
classes = [s for s in symbols if s['type'] == 'class']
methods = [s for s in symbols if s['type'] == 'method']
functions = [s for s in symbols if s['type'] == 'function']
globals_assign = [s for s in symbols if s['type'] == 'global_assign']

# Refined inventory
inventory = {
    "total_lines": total_lines,
    "imports": [s['name'] for s in imports],
    "classes": {s['name']: {"line": s['line'], "end": s['end'], "methods": []} for s in classes},
    "methods": {s['name']: {"line": s['line'], "end": s['end'], "deps": list(caller_to_callees.get(s['name'], set()))} for s in methods},
    "functions": {s['name']: {"line": s['line'], "end": s['end'], "deps": list(caller_to_callees.get(s['name'], set()))} for s in functions},
}

# Assign methods to their class
for s in methods:
    parts = s['name'].split('.', 1)
    if len(parts) == 2:
        cls_name, method_name = parts
        if cls_name in inventory['classes']:
            inventory['classes'][cls_name]['methods'].append(method_name)

###############################################################################
# 5. Special inventories via regex-free AST walking
###############################################################################
thread_targets = []
timer_calls = []
queue_refs = []
socket_refs = []
scapy_refs = []
subprocess_refs = []
file_paths = set()
json_dicts = []
widget_builders = []
event_bindings = []
shared_state = set()

for node in ast.walk(tree):
    # thread targets
    if isinstance(node, ast.Call):
        fn = node_name(node.func)
        if 'threading.Thread' in fn:
            for kw in node.keywords:
                if kw.arg == 'target' and isinstance(kw.value, ast.Name):
                    thread_targets.append(kw.value.id)
                elif kw.arg == 'target' and isinstance(kw.value, ast.Attribute):
                    thread_targets.append(node_name(kw.value))
        if 'root.after' in fn or '.after(' in fn:
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    timer_calls.append(arg.id)
                elif isinstance(arg, ast.Attribute):
                    timer_calls.append(node_name(arg))
        if 'subprocess.run' in fn or 'subprocess.' in fn:
            subprocess_refs.append(node.lineno)
        if 'os.system' in fn or 'os.system(' in fn:
            subprocess_refs.append(node.lineno)
    # scapy references
    if isinstance(node, ast.Attribute):
        if node.attr in ('sniff', 'srp', 'ARP', 'Ether', 'IP', 'TCP', 'UDP', 'ICMP', 'Raw', 'wrpcap', 'rdpcap', 'get_if_list', 'get_working_ifaces'):
            scapy_refs.append(node.lineno)
    # queue references
    if isinstance(node, ast.Name) and 'queue' in node.id.lower():
        queue_refs.append(node.id)
    if isinstance(node, ast.Attribute) and 'queue' in node.attr.lower():
        queue_refs.append(node.attr)
    # socket references
    if isinstance(node, ast.Attribute) and node.attr in ('socket', 'SOCK_STREAM', 'SOCK_DGRAM', 'AF_INET', 'SO_REUSEADDR', 'connect_ex', 'bind', 'listen', 'accept', 'send', 'recv', 'close'):
        socket_refs.append(node.lineno)
    # file paths
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if 'network_analyzer_data' in node.value or '/tmp/' in node.value or 'known_devices.json' in node.value:
            file_paths.add(node.value)
    # JSON schemas (dict literals at module level or in __init__)
    if isinstance(node, ast.Dict):
        keys = [node_name(k) for k in node.keys if k]
        if any('parental' in k.lower() for k in keys):
            json_dicts.append(node.lineno)

# Widget builders: methods containing 'ttk.' or 'tk.' with 'Treeview', 'Button', 'Label', etc.
for s in methods:
    if any(w in s['name'].lower() for w in ('create_', 'build_', 'setup_')):
        widget_builders.append(s['name'])

# Event bindings: methods containing 'bind('
for s in methods:
    widget_builders.append(s['name'])

###############################################################################
# 6. Circular dependency detection (simplified)
###############################################################################
cycles = []
all_funcs = list(func_map.keys())
visited = set()

def dfs(node, path):
    if node in path:
        cycle = path[path.index(node):] + [node]
        cycles.append(" → ".join(cycle))
        return
    if node in visited:
        return
    visited.add(node)
    path.append(node)
    for callee in caller_to_callees.get(node, set()):
        if callee in func_map:
            dfs(callee, path[:])

for fn in all_funcs:
    dfs(fn, [])

# Deduplicate cycles
cycles = list(set(cycles))

###############################################################################
# 7. Module mapping suggestions
###############################################################################
module_map = {}
for s in methods:
    parts = s['name'].split('.', 1)
    if len(parts) == 2:
        cls_name, method_name = parts
        # Suggest module based on method name
        if method_name.startswith('create_'):
            tab_name = method_name.replace('create_', '').replace('_tab', '')
            module_map[s['name']] = f"ui/{tab_name}.py"
        elif method_name.startswith(('quick_scan', 'full_scan', 'deep_scan', 'run_', 'start_scan', 'stop_scan')):
            module_map[s['name']] = "services/scanner.py"
        elif 'parental' in method_name or method_name.startswith(('toggle_dns', 'capture_dns', 'content_filter', 'is_curfew', 'periodic_parental')):
            module_map[s['name']] = "services/parental_control.py"
        elif 'monitor' in method_name:
            module_map[s['name']] = "services/monitor.py"
        elif 'netcat' in method_name:
            module_map[s['name']] = "services/netcat.py"
        elif 'packet' in method_name or 'capture' in method_name:
            module_map[s['name']] = "services/packet_capture.py"
        elif 'save_data' in method_name or 'load_data' in method_name or 'backup' in method_name:
            module_map[s['name']] = "services/persistence.py"
        elif 'log' in method_name:
            module_map[s['name']] = "services/logging_service.py"
        elif 'device' in method_name:
            module_map[s['name']] = "models/device.py"
        elif method_name.startswith(('discover_', 'get_gateway', 'update_network', '_is_same')):
            module_map[s['name']] = "services/network_discovery.py"
        else:
            module_map[s['name']] = "app.py"

###############################################################################
# 8. Write reports
###############################################################################
report = {
    "total_lines": total_lines,
    "ast_valid": True,
    "inventory": {
        "imports": len(imports),
        "classes": len(classes),
        "methods": len(methods),
        "functions": len(functions),
        "global_assignments": len(globals_assign),
    },
    "class_details": inventory['classes'],
    "thread_targets": list(set(thread_targets)),
    "timer_callbacks": list(set(timer_calls)),
    "scapy_operations": len(scapy_refs),
    "subprocess_calls": len(subprocess_refs),
    "file_paths": sorted(file_paths),
    "json_dict_locations": json_dicts,
    "widget_builders": widget_builders,
    "circular_dependency_cycles": cycles[:20],
    "module_suggestions": module_map,
}

report_path = REPO / "refactor_report.json"
with open(report_path, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, default=str)
print(f"✅ Report written to {report_path}")

# Markdown summary
md = f"""# Refactor Report — main.py

**Total lines:** {total_lines}  
**AST valid:** True

---

## Inventory

| Category | Count |
|---|---|
| Imports | {len(imports)} |
| Classes | {len(classes)} |
| Methods | {len(methods)} |
| Functions | {len(functions)} |
| Global assignments | {len(globals_assign)} |
| Thread targets | {len(set(thread_targets))} |
| Scapy operations | {len(scapy_refs)} |
| Subprocess calls | {len(subprocess_refs)} |

## Classes

"""
for cls_name, info in inventory['classes'].items():
    md += f"- **{cls_name}** (line {info['line']}-{info['end']}, {len(info['methods'])} methods)\\n"

md += f"""
## Thread Targets

{', '.join(sorted(set(thread_targets))) if thread_targets else 'None detected'}

## Timer Callbacks

{', '.join(sorted(set(timer_calls))) if timer_calls else 'None detected'}

## File Paths

"""
for p in sorted(file_paths):
    md += f"- `{p}`\\n"

md += """
## Circular Dependency Cycles

"""
if cycles:
    for c in cycles[:20]:
        md += f"- {c}\\n"
else:
    md += "None detected (cycle detection limited to direct calls)\\n"

md += """
## Module Mapping (suggested)

| Symbol | Suggested Module |
|---|---|
"""
for sym, mod in sorted(module_map.items())[:100]:
    md += f"| `{sym}` | `{mod}` |\\n"

md_path = REPO / "refactor_report.md"
with open(md_path, "w", encoding="utf-8") as f:
    f.write(md)
print(f"✅ Report written to {md_path}")
