#!/usr/bin/env python3
import os
import sys
import traceback
import argparse
import multiprocessing as mp
import queue
import time

from dtype import Value
from disassembly import Disassembly
from automaton import Automaton

def parse_args():
    parser = argparse.ArgumentParser(
        description="Build automaton from PLC application disassembly"
    )
    parser.add_argument('disassembly',
            help="Path to the disassembly (.lst) file. If a directory is given, all disassembly files within will be analyzed")
    parser.add_argument('fb_dir',
            help="Directory containing function block disassembly")
    parser.add_argument('output',
            help="Automaton output directory/filename")
    parser.add_argument('-M', '--max', default='0xFFFFFFFF',
            help="Max input")
    parser.add_argument('-s', '--skip', action='store_true',
            help="(Directory mode only) Skip the disassembly which already has the corresponding output")
    parser.add_argument('-d', '--debug', action='store_true',
            help="Enable debug mode")
    parser.add_argument('-c', '--cpu', type=int, default=1,
            help="Number of parallel tasks in multiprocessing. Default is 1")
    parser.add_argument('-q', '--quiet', action='store_true',
            help='Suppress all display message')
    return parser.parse_args()

class AutomatonBuilder(object):
    def __init__(self, machine):
        self.machine = machine
        self.machine.reset()

    def generate_automaton(self, max_input, output_queue, display_base, refresh_interval=1.0, debug=False):
        total_time_start = time.time()
        roll_back_time = 0
        roll_back_counter = 0
        if debug:
            state_index = {}
        # Only inputs causing a state change will be saved
        input_sequence = []
        current_state = self.machine.state
        current_input = Value(0)
        states_input = {current_state:current_input}
        states_completed = set()
        states_with_timer_counter = set()
        # Sequence of input to reach each state from machine.reset()
        path_to_state = {self.machine.state:[]}
        automaton = Automaton()
        # Record all adjacent states which have timers/counters to avoid deadlock
        loop_states_with_timer_counter = set()

        while len(states_input) > 0:
            new_transition = None
            roll_back_state = None
            if debug:
                print("--------------------")

            current_state = self.machine.state
            if debug:
                if current_state not in state_index:
                    state_index[current_state] = len(state_index)
                print("Current state: {}".format(state_index[current_state]))
            if current_state in states_completed:
                if debug:
                    print("Current state has been completed")
                # Randomly pick an incomplete state to resume
                roll_back_state = list(states_input.keys())[0]
            else:
                if len(self.machine.timers) > 0 or len(self.machine.counters) > 0:
                    # The current state has running timers and/or counters
                    # Run a single scan cycle with no input to transition into the
                    # next state
                    if debug:
                        if len(self.machine.timers):
                            print("Timers: {}".format(self.machine.timers))
                        if len(self.machine.counters):
                            print("Counters: {}".format(self.machine.counters))
                    states_with_timer_counter.add(current_state)
                    # Remove the current state from states_input because no input
                    # can be tested on a state with timer/counter activated
                    if current_state in states_input:
                        if debug:
                            print("Remove state {} from states_input".format(state_index[current_state]))
                        states_input.pop(current_state)

                    if current_state in loop_states_with_timer_counter:
                        # There is a loop of states which all have timer/counter
                        # This is a dead lock
                        # A roll back is needed
                        if debug:
                            print("A loop of states with timers/counters is found")
                        # Add all states in this loop to states_completed
                        states_completed.update(loop_states_with_timer_counter)
                        loop_states_with_timer_counter.clear()
                        if len(states_input) > 0:
                            # Check if there is any other incomplete state and
                            # randomly pick one to resume
                            roll_back_state = list(states_input.keys())[0]
                        else:
                            # There is no state without timer/counter to revert
                            # back to
                            if debug:
                                print("No state without timer/counter can be reverted back to")
                            break
                    else:
                        # Record the current state and perform a no input scan
                        # cycle
                        loop_states_with_timer_counter.add(current_state)
                        new_transition = self.machine.transition
                        # Use the last input
                        self.machine.scan_cycle(debug=debug)
                        next_state = self.machine.state
                else:
                    # The current state has no timers or counters
                    loop_states_with_timer_counter.clear()
                    # Fetch the input to be used for the current state and perform
                    # a single scan cycle to transition into the next state
                    current_input = states_input[current_state]
                    if debug:
                        print("Input: {}".format(current_input))

                    # Perform a single scan cycle with the input for the current
                    # state
                    self.machine.scan_cycle(inputs=current_input, debug=debug)
                    next_state = self.machine.state
                    if states_input[current_state] == max_input:
                        # Current state has been completed
                        if debug:
                            print("Current state completed")
                            print("Remove state {} from states_input".format(state_index[current_state]))
                        states_input.pop(current_state)
                        states_completed.add(current_state)
                        if current_state == next_state and len(states_input) > 0:
                            # The current state completes and no transition of
                            # state occurred. If there are still other states left
                            # incomplete in states_input, randomly pick one to
                            # resume
                            roll_back_state = list(states_input.keys())[0]
                    else:
                        # Next time the the current_state is reached, a new input
                        # should be used
                        states_input[current_state] += 1
                        if debug:
                            print("states_input[{}] value updated to {}".format(state_index[current_state],
                                states_input[current_state]))

                if next_state != current_state:
                    # The next state is different from current state
                    # The new transition needs to be recorded in the automaton
                    new_transition = self.machine.transition
                    # Input sequence needs to be updated due to change of state
                    input_sequence.append(current_input)

                if debug:
                    if next_state not in state_index:
                        state_index[next_state] = len(state_index)
                    print("Next state: {}".format(state_index[next_state]))
                if new_transition:
                    # If next_state has never been seen before, initialize the
                    # node (except if the next_state has timer/counter)
                    if next_state not in states_input and next_state not in states_completed and next_state not in states_with_timer_counter:
                        if debug:
                            print("New state found")
                        states_input[next_state] = Value(0)
                        if debug:
                            print("New state {} added to states_input".format(state_index[next_state]))
                    if debug:
                        print("New transition found")
                    automaton.add(current_state, new_transition, next_state)
                    # Check if path_to_state needs to be created or updated
                    if (next_state not in path_to_state) or (len(path_to_state[current_state]) + 1 < len(path_to_state[next_state])):
                        # Copy the path to the current_state
                        new_path = [i for i in path_to_state[current_state]]
                        # Add the input which causes the transition from
                        # current_state to next_state
                        new_path.append(current_input)
                        path_to_state[next_state] = new_path
                        if debug:
                            print("Path to {} updated to: {}".format(state_index[next_state], new_path))

            # A roll back is needed
            if roll_back_state:
                time_start = time.time()
                if debug:
                    print("Rolling back to state {}".format(state_index[roll_back_state]))
                    print("Steps: {}".format(path_to_state[roll_back_state]))
                input_sequence = []
                self.machine.reset()
                for current_input in path_to_state[roll_back_state]:
                    current_state = self.machine.state
                    if debug:
                        print("[Roll back]: Current state: {}".format(state_index[current_state]))
                    if len(self.machine.timers) or len(self.machine.counters):
                        if debug:
                            print("[Roll back]: Ignoring timers {} and counters {}".format(
                                self.machine.timers,
                                self.machine.counters
                                ))
                    input_sequence.append(current_input)
                    if debug:
                        print("[Roll back]: {}".format(self.machine.transition))
                    self.machine.scan_cycle(inputs=current_input, debug=debug)
                if self.machine.state != roll_back_state:
                    if debug:
                        raise Exception("[Roll back]: Incorrect state: {}".format(state_index[self.machine.state]))
                    else:
                        raise Exception("[Roll back]: Incorrect state: {}".format(self.machine.state))
                if debug:
                    print("[Roll back]: Rolled back to state {}".format(state_index[self.machine.state]))
                roll_back_time += time.time() - time_start
                roll_back_counter += 1
                roll_back_state = None

            if not debug:
                # Print progress percentage
                if not hasattr(self, "last_refresh"):
                    self.last_refresh = 0
                current_time = time.time()
                if current_time - self.last_refresh >= refresh_interval:
                    output_queue.put((display_base, "Total states discovered: {}".format(len(automaton))))
                    progress_total = (max_input + 1) * len(automaton)
                    progress_incomplete = 0
                    for i in states_input.values():
                        progress_incomplete += max_input - i.value
                    try:
                        progress_ratio = 1 - float(progress_incomplete) / progress_total
                    except ZeroDivisionError:
                        progress_ratio = 0
                    output_queue.put((display_base + 1, "Progress: {:.2%}".format(progress_ratio)))
                    output_queue.put((display_base + 3, "Total time: {:.2f}s".format(time.time() - total_time_start)))
                    output_queue.put((display_base + 4, "Roll back counter: {}".format(roll_back_counter)))
                    output_queue.put((display_base + 5, "Roll back time: {:.2f}s".format(roll_back_time)))
                    self.last_refresh = current_time
        if debug:
            print("All states completed")
        else:
            # Clear the lines
            output_queue.put((display_base, ""))
            output_queue.put((display_base + 1, ""))
        return automaton

def main(disassembly_filename, function_block_disassembly_dir, output_path, max_input, output_queue, display_base, debug=False):
    disassembly = Disassembly(fromfile=disassembly_filename)
    parser = disassembly.get_parser(function_block_disassembly_dir)
    automaton_builder = AutomatonBuilder(parser)
    automaton = automaton_builder.generate_automaton(max_input, output_queue, display_base, debug=debug)
    automaton.export(filename=output_path)

# Wrapper method for the main workflow
# Keeps processing disassembly files from the queue until it is empty
def main_mp_wrapper(worker_id, disassembly_filenames, options, output_queue, display_base):
    output_queue.put((display_base, "Worker: {}".format(worker_id)))
    while True:
        disassembly_filename = disassembly_filenames.get()
        if disassembly_filename is None:
            # Encountered the "Poison Pill"
            # Put it back for the other processes to see and exit
            disassembly_filenames.put(None)
            output_queue.put((display_base + 1, "Finished"))
            break
        else:
            _, filename = os.path.split(disassembly_filename)
            output_path = os.path.join(options.output, filename.split('.')[0] + '.gml')
            err_path = os.path.join(options.output, filename.split('.')[0] + '.log')
            output_queue.put((display_base + 1,
                    "Building automaton for {}".format(os.path.split(filename)[-1])))
            try:
                main(disassembly_filename, options.fb_dir, output_path, max_input, output_queue,
                        display_base+2)
                time.sleep(1)
            except:
                with open(err_path, 'w') as f:
                    f.write(traceback.format_exc())
            finally:
                with completed_counter.get_lock():
                    completed_counter.value += 1

if __name__ == '__main__':
    # Parse command line arguments
    options = parse_args()
    max_input = int(options.max, 0)

    if options.debug:
        # In debug mode, only a single file can be used as the disassembly
        # argument, and no output is needed
        # No progress status will be shown in debug mode to prevent
        # interfering with the debug session
        main(options.disassembly, options.fb_dir, None, max_input, None, None, debug=True)
    else:
        disassembly_filenames = mp.Queue()
        if os.path.isdir(options.disassembly):
            # If a directory is given as disassembly argument, the output argument
            # also has to be a directory
            if not os.path.isdir(options.output):
                raise Exception("Output needs to be a directory if disassembly is a directory")
            total_counter = 0
            for filename in sorted(os.listdir(options.disassembly),
                    key=lambda filename: int(filename.split('.')[0]) if filename.split('.')[0].isdigit() else 0):
                if filename.startswith(".") or not filename.endswith(".lst"):
                    continue
                # If an output already exists and skip argument is set, skip
                # processing the disassembly file
                output_path = os.path.join(options.output, filename.split('.')[0] + '.gml')
                if options.skip and os.path.isfile(output_path):
                    continue
                # Place all disassembly files in a queue
                disassembly_filenames.put(os.path.join(options.disassembly, filename))
                total_counter += 1
        else:
            disassembly_filenames.put(options.disassembly)
            total_counter = 1
        # Put a "Poison Pill" into the queue so that a worker processes who
        # sees it knows that there is no more item in the queue
        disassembly_filenames.put(None)

        # Share a counter across all processes to keep count of how many
        # disassembly files have been processed
        completed_counter = mp.Value('i', 0)

        # Pipe output to a queue to avoid racing condition
        # The message will be rendered by the main process
        output_queue = mp.Queue()

        if not options.quiet:
            # Clear screen
            sys.stdout.write("\x1b[2J")
            sys.stdout.flush()

        # Initialize the worker processes
        workers = []
        for worker_id in range(options.cpu):
            worker = mp.Process(target=main_mp_wrapper, args=(
                worker_id, disassembly_filenames, options, output_queue, worker_id * 5 + 3))
            worker.start()
            workers.append(worker)

        # The main process keeps track of how many disassembly files have been
        # processed and render the output messages enqueued by the worker
        # processes
        last_progress = -1
        # Keep running until all disassembly files have been processed
        while last_progress < total_counter:
            with completed_counter.get_lock():
                # To avoid unnecessary queue operation, only update the total
                # progress whenever it changes
                if completed_counter.value != last_progress:
                    output_queue.put((1, "Total progress: {}/{}".format(completed_counter.value, total_counter)))
                    last_progress = completed_counter.value
            # Write all queued messages to stdout
            while True:
                try:
                    row, msg = output_queue.get(block=False)
                except queue.Empty:
                    break
                else:
                    if not options.quiet:
                        sys.stdout.write("\x1b[{};1H\x1b[K".format(row) + msg + '\n')
            if not options.quiet:
                sys.stdout.flush()
            time.sleep(0.1)

        # Wait for all worker processes to join
        for worker in workers:
            worker.join()

        if not options.quiet:
            # Clear screen
            sys.stdout.write("\x1b[1;1H\x1b[2J")
            sys.stdout.flush()
