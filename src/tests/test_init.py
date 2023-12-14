# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import unittest
from init import _TreeIterator


class TestInit(unittest.TestCase):

    def test_tree_iterator(self) -> None:
        list1 = [1, 2, 3]
        list2 = [4, list1, 5]
        list3 = [list1, [], list2, 6]
        list4 = [list2, [8], [list3], [[9]]]
        expected_list = [4, 1, 2, 3, 5, 8, 1, 2, 3, 4, 1, 2, 3, 5, 6, 9]

        iterator = _TreeIterator(list4)

        result_len = iterator.len()
        result_list = [item for item in iterator]

        self.assertEqual(len(expected_list), result_len, 'Invalid length')
        self.assertSequenceEqual(expected_list, result_list, 'Invalid list')
