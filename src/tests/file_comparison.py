# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import tree_sitter
import tree_sitter_c
import re

C_LANGUAGE = tree_sitter.Language(tree_sitter_c.lib_path, 'c')


def compare_aot_literals(file1, file2):
    def read_set(file):
        ret = set()
        with open(file) as f:
            line = f.readline()
            while line:
                ret.add(line.partition('=')[2])
                line = f.readline()
        return ret

    set1 = read_set(file1)
    set2 = read_set(file2)
    diff1 = set1 - set2
    diff2 = set2 - set1
    if diff1 or diff2:
        msg = ''
        for d in diff1:
            msg += f'+{d}'
        for d in diff2:
            msg += f'-{d}'
        return False, msg
    else:
        return True, ''


def _diff_str(node1, node2):
    line, col = node1.start_point
    msg = f'At {line},{col}:\n'
    if node1:
        msg += f'+{node1.text.decode().strip()}\n'
    if node2:
        msg += f'-{node2.text.decode().strip()}\n'
    return msg


def _diff_node_lists(node_list1, node_list2):
    msg = ''
    set1 = {node.text for node in node_list1}
    set2 = {node.text for node in node_list2}
    for node in set1 - set2:
        msg += f'+{node.decode().strip()}\n'
    for node in set2 - set1:
        msg += f'-{node.decode().strip()}\n'
    return msg


def _get_capture_with_tag(captures, tag):
    for capture in captures:
        if capture[1] == tag:
            return capture[0]


class CComparator:

    COMMENT_QUERY = '''
    (comment) @ignore
    '''
    IGNORE_TAG = 'ignore'

    def __init__(self, file1, file2, special_nodes):
        parser = tree_sitter.Parser()
        parser.set_language(C_LANGUAGE)

        with open(file1, 'rb') as f:
            self.root1 = parser.parse(f.read()).root_node

        with open(file2, 'rb') as f:
            self.root2 = parser.parse(f.read()).root_node

        def nop(self, captures1, captures2):
            return True, ''
        self.special_nodes = {CComparator.COMMENT_QUERY: nop}
        for query, comparator in special_nodes.items():
            self.special_nodes[query] = comparator
        self.unordered_types = ['declaration', 'function_definition']

        self.ignored_nodes1 = []
        self.ignored_nodes2 = []

        self.success = True
        self.msg = ''

    def _group_nodes(self, nodes, ignored):
        grouped = []
        current_group = None
        current_type = None
        for node in nodes:
            if node in ignored:
                continue
            if current_type is not None:
                if node.type == current_type:
                    current_group.append(node)
                    continue
                grouped.append(current_group)
                current_type = None
                current_group = None
            if node.type in self.unordered_types:
                current_type = node.type
                current_group = [node]
                continue
            grouped.append(node)
        return grouped

    def _unwrap_header_guard(self):
        if len(self.root1.children) == 1 \
                and self.root1.children[0].type == 'preproc_ifdef':
            if len(self.root2.children) == 1 \
                    and self.root2.children[0].type == 'preproc_ifdef':
                self.root1 = self.root1.children[0]
                self.root2 = self.root2.children[0]
                return
            self.success = False
            self.msg += '+Header guard'
        elif len(self.root2.children) == 1 \
                and self.root2.children[0].type == 'preproc_ifdef':
            self.success = False
            self.msg += '-Header guard'

    def _handle_special_nodes(self):
        for query, comparator in self.special_nodes.items():
            query = C_LANGUAGE.query(query)
            captures1 = query.captures(self.root1)
            captures2 = query.captures(self.root2)

            r, m = comparator(self, captures1, captures2)
            if not r:
                self.success = False
                self.msg += m

            ignore = _get_capture_with_tag(captures1, CComparator.IGNORE_TAG)
            if ignore is not None:
                self.ignored_nodes1.append(ignore)

            ignore = _get_capture_with_tag(captures2, CComparator.IGNORE_TAG)
            if ignore is not None:
                self.ignored_nodes2.append(ignore)

    def compare(self):
        self._unwrap_header_guard()
        self._handle_special_nodes()

        nodes1 = self._group_nodes(self.root1.named_children, self.ignored_nodes1)
        nodes2 = self._group_nodes(self.root2.named_children, self.ignored_nodes2)

        for node1, node2 in zip(nodes1, nodes2):
            if isinstance(node1, list) and isinstance(node2, list):
                m = _diff_node_lists(node1, node2)
                if m:
                    self.success = False
                    self.msg += m
                continue

            if isinstance(node1, list):
                return False, _diff_str(node1[0], node2)
            if isinstance(node2, list):
                return False, _diff_str(node1, node2[0])

            if node1.text != node2.text:
                return False, _diff_str(node1, node2)

        if len(nodes1) < len(nodes2):
            for node in nodes2[len(nodes1):]:
                self.success = False
                self.msg += _diff_str(None, node)
        if len(nodes1) > len(nodes2):
            for node in nodes1[len(nodes2):]:
                self.success = False
                self.msg += _diff_str(node, None)

        return self.success, self.msg

    def compare_C_simple(file1, file2):
        return CComparator(file1, file2, {}).compare()


class FptrStubCComparator(CComparator):

    FPTRSTUB_PAIR_ARRAY_QUERY = '''
        (declaration
            declarator: (init_declarator
                declarator: (array_declarator
                    declarator: (identifier) @identifier
                    (#eq? @identifier "fptrstub_pair_array")
                )
                value: (initializer_list) @value
            )
        ) @ignore
    '''
    INITIALIZE_FUNCTION_POINTER_STUBS_QUERY = '''
        (function_definition
            declarator: (function_declarator
                declarator: (identifier) @identifier
                (#eq? @identifier "initialize_function_pointer_stubs")
            )
            body: (compound_statement) @body
        ) @ignore
    '''
    AOT_KFLAT_INITIALIZE_GLOBAL_VARIABLES_QUERY = '''
        (function_definition
            declarator: (function_declarator
                declarator: (identifier) @identifier
                (#eq? @identifier "aot_kflat_initialize_global_variables")
            )
            body: (compound_statement) @body
        ) @ignore
    '''

    def __init__(self, file1, file2):
        self.fptrstub_pair_array1 = []
        self.fptrstub_pair_array2 = []

        super().__init__(file1, file2, {
            FptrStubCComparator.FPTRSTUB_PAIR_ARRAY_QUERY:
                FptrStubCComparator._compare_fptrstub_pair_array,
            FptrStubCComparator.INITIALIZE_FUNCTION_POINTER_STUBS_QUERY:
                FptrStubCComparator._compare_initialize_function_pointer_stubs,
            FptrStubCComparator.AOT_KFLAT_INITIALIZE_GLOBAL_VARIABLES_QUERY:
                FptrStubCComparator._compare_aot_kflat_initialize_global_variables,
        })

    def _compare_fptrstub_pair_array(self, captures1, captures2):
        values1 = _get_capture_with_tag(captures1, 'value')
        values2 = _get_capture_with_tag(captures2, 'value')

        msg =_diff_node_lists(values1.named_children, values2.named_children)
        
        def get_fptrstub_name(node):
            # extract function name from quotes ignoring optional module name in square brackets
            match = re.search(r'"(\w+)(?: \[\w+\])?"', node.text.decode())
            if not match:
                return None
            return match.group(1)

        for node in values1.named_children:
            self.fptrstub_pair_array1.append(get_fptrstub_name(node))
        for node in values2.named_children:
            self.fptrstub_pair_array2.append(get_fptrstub_name(node))
        
        return len(msg) == 0, msg
    
    def _compare_initialize_function_pointer_stubs(self, captures1, captures2):
        body1 = _get_capture_with_tag(captures1, 'body')
        body2 = _get_capture_with_tag(captures2, 'body')

        def validate_initialization(nodes, name_array):
            initialized = set()
            msg = ''
            for node in nodes:
                regex = r'fptrstub_pair_array\[(\d+)\]\.address = (\w+);'
                match = re.match(regex, node.text.decode())
                index = int(match.group(1))
                name = match.group(2)

                line, col = node.start_point

                if index >= len(name_array):
                    msg += f'\tat {line},{col}: index {index} is too big, array size is {len(name_array)}\n'
                    continue
                
                initialized.add(index)
                if not name.endswith(name_array[index]):
                    msg += f'\tat {line},{col}: function pointer name should be {name_array[index]}\n'
                    continue
            for i in range(len(name_array)):
                if i not in initialized:
                    msg += f'\tfptrstub_pair_array is not initialized at index {i}\n'
            return msg
        
        msg = ''
        m = validate_initialization(body1.named_children, self.fptrstub_pair_array1)
        if m:
            msg += f'initialize_function_pointer_stubs in file 1:\n{m}'
        m = validate_initialization(body2.named_children, self.fptrstub_pair_array2)
        if m:
            msg += f'initialize_function_pointer_stubs in file 2:\n{m}'
        
        return len(msg) == 0, msg

    def _compare_aot_kflat_initialize_global_variables(self, captures1, captures2):
        body1 = _get_capture_with_tag(captures1, 'body')
        body2 = _get_capture_with_tag(captures2, 'body')

        msg = _diff_node_lists(body1.named_children, body2.named_children)

        return len(msg) == 0, f'aot_kflat_initialize_global_variables:\n{msg}'

    def compare_fptr_stub_c(file1, file2):
        return FptrStubCComparator(file1, file2).compare()
