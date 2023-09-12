# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import clang.cindex


def _read_line_set(file):
    with open(file) as f:
        return set(f.readlines())


def _compare_sets(set1, set2):
    diff1 = set1 - set2
    diff2 = set2 - set1
    if diff1 or diff2:
        msg = ''
        for d in diff1:
            msg += f'+{d}\n'
        for d in diff2:
            msg += f'-{d}\n'
        return False, msg
    else:
        return True, None


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
        return True, None


def compare_C_simple(file1, file2):
    return CComparator(file1, file2, {}).compare()


class CComparator:

    def __init__(self, file1, file2, special_symbols):
        self.nodes1, self.src1 = CComparator._read_file(file1)
        self.nodes2, self.src2 = CComparator._read_file(file2)
        self.special_symbols = special_symbols

    def _get_node_str(node, src):
        start = node.extent.start
        end = node.extent.end

        if start.line == end.line:
            return src[start.line - 1][start.column - 1:end.column - 1]

        s = ''
        for i in range(start.line - 1, end.line - 1):
            s += src[i]
        s += src[end.line - 1]

        return s

    def _read_file(file):
        tu = clang.cindex.Index.create().parse(file)
        d = {}
        for child in tu.cursor.get_children():
            if child.location.file.name != file:
                continue
            if child.displayname not in d:
                d[child.displayname] = []
            d[child.displayname].append(child)

        with open(file) as f:
            src = f.readlines()
        return d, src

    def _compare_node(self, node1, node2):
        msg = ''
        name = node1.displayname
        if name in self.special_symbols:
            result, symbol_msg = self.special_symbols[name](node1, node2)
            if not result:
                msg += f'Difference in {name}:\n'
                msg += symbol_msg
        else:
            str1 = CComparator._get_node_str(node1, self.src1)
            str2 = CComparator._get_node_str(node2, self.src2)
            if str1 != str2:
                msg += f'Difference in {name}:\n'
                msg += str1
                msg += 'changed into\n'
                msg += str2
        return len(msg) == 0, msg

    def compare(self):
        msg = ''
        for name, nodes1 in self.nodes1.items():
            if name not in self.nodes2:
                msg += f'+{name}\n'
                continue
            nodes2 = self.nodes2[name]
            if len(nodes1) < len(nodes2):
                for node in nodes2[len(nodes1):]:
                    msg += f'-{node.displayname}'
                nodes2 = nodes2[:len(nodes1)]
            if len(nodes2) < len(nodes1):
                for node in nodes1[len(nodes2):]:
                    msg += f'+{node.displayname}'
                nodes1 = nodes1[:len(nodes2)]
            for node1, node2 in zip(nodes1, nodes2):
                result, node_msg = self._compare_node(node1, node2)
                if not result:
                    msg += node_msg
            self.nodes2.pop(name)
        for name in self.nodes2.keys():
            msg += f'-{name}\n'
        return len(msg) == 0, msg

    def compare_unordered_function(self, node1, node2):
        lines1 = CComparator._get_node_str(node1, self.src1).splitlines()
        lines2 = CComparator._get_node_str(node2, self.src2).splitlines()

        msg = ''
        if lines1[0] != lines2[0]:
            msg += f'Declaration changed:\n{lines2[0]}into\n{lines1[0]}'
        if lines1[-1] != lines2[-1]:
            msg += f'{lines2[-1]} -> {lines1[-1]}'

        set1 = set(lines1[1:-1])
        set2 = set(lines2[1:-1])
        result, set_msg = _compare_sets(set1, set2)
        if not result:
            msg += set_msg

        return len(msg) == 0, msg


class FptrStubCComparator(CComparator):

    def __init__(self, file1, file2):
        special_symbols = {
            'aot_kflat_initialize_global_variables()': self.compare_unordered_function,
            'fptrstub_pair_array': self._compare_fptrstub_pair_array,
            'initialize_function_pointer_stubs()': self._verify_initialize_function_pointer_stubs,
        }
        super().__init__(file1, file2, special_symbols)

    def _compare_fptrstub_pair_array(self, node1, node2):
        lines1 = FptrStubCComparator._get_node_str(node1, self.src1).splitlines()
        lines2 = FptrStubCComparator._get_node_str(node2, self.src2).splitlines()

        msg = ''
        if lines1[0] != lines2[0]:
            msg += f'Declaration changed:\n{lines2[0]}\ninto\n{lines1[0]}\n'
        if lines1[-1] != lines2[-1]:
            return False, f'{lines2[-1]} -> {lines1[-1]}'

        self.fptrstub_pair_array = []
        for entry in lines1[1:-1]:
            func_name = entry.split('"')[1]
            self.fptrstub_pair_array.append(func_name)

        set1 = set(lines1[1:-1])
        set2 = set(lines2[1:-1])

        result, set_msg = _compare_sets(set1, set2)
        if not result:
            msg += set_msg

        return len(msg) == 0, msg

    def _verify_initialize_function_pointer_stubs(self, node1, node2):
        lines1 = FptrStubCComparator._get_node_str(node1, self.src1).splitlines()
        lines2 = FptrStubCComparator._get_node_str(node2, self.src2).splitlines()

        msg = ''
        if lines1[0] != lines2[0]:
            msg += f'Declaration changed:\n{lines2[0]}into\n{lines1[0]}'
        if lines1[-1] != lines2[-1]:
            msg += f'{lines2[-1]} -> {lines1[-1]}'

        for line in lines1[1:-1]:
            index = int(line[line.find('[') + 1:line.find(']')])
            name = line.split('=')[-1].lstrip()[:-1]
            if self.fptrstub_pair_array[index] != name:
                msg += f'Invalid function name at index {index}: {name}, should be {self.fptrstub_pair_array[index]}\n'
            self.fptrstub_pair_array[index] = None

        for i, v in enumerate(self.fptrstub_pair_array):
            if v:
                msg += f'Missing fptrstub_pair_array index: {i}\n'

        return len(msg) == 0, msg

    def compare_fptr_stub_c(file1, file2):
        return FptrStubCComparator(file1, file2).compare()
