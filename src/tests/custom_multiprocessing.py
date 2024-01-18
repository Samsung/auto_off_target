# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

from multiprocessing import Process, Queue
from typing import Callable, Tuple, TypeVar, Generic, Iterable, List, Optional

T = TypeVar('T', bound=Tuple)
U = TypeVar('U')


# Python's ProcessPoolExecutor reuses created processes,
# which causes issues with libftdb.
# This is a custom executor that remedies those issues.
class ProcessExecutor(Generic[T, U]):
    result_queue: 'Queue[Tuple[int, U]]'
    processes: List[Optional[Process]]
    results: List[Optional[U]]
    running_count: int
    count: int

    def __init__(
        self,
        count: int,
    ) -> None:
        self.count = count

    def _target_wrapper(
        self,
        target: Callable[..., U],
        args: T,
        index: int,
    ) -> None:
        result = target(*args)
        self.result_queue.put((index, result))

    def _join_process(self) -> None:
        index, result = self.result_queue.get()
        self.results[index] = result

        self.processes[index].join()  # type: ignore
        self.processes[index].close()  # type: ignore

        self.running_count -= 1

    def apply(
        self,
        target: Callable[..., U],
        args_list: List[T],
        callback: Optional[Callable[[], None]],
    ) -> Iterable[U]:
        self.result_queue = Queue()
        self.processes = [None] * len(args_list)
        self.results = [None] * len(args_list)
        self.running_count = 0

        for i, args in enumerate(args_list):
            while self.running_count >= self.count:
                self._join_process()
                if callback:
                    callback()

            process = Process(
                target=self._target_wrapper,
                args=(target, args, i),
            )
            process.start()
            self.processes[i] = process
            self.running_count += 1

        while self.running_count > 0:
            self._join_process()
            if callback:
                callback()

        return self.results  # type: ignore
