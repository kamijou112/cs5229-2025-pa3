# Network Monitoring with Sketches (4%)

## Introduction

Sketches are commonly used probabilistic data structures for counting, given their sublinear memory requirements.

In this exercise, we will keep track of per-flow packet counts using sketches.
We will use the sketches to perform two tasks:
(1) heavy-hitter detection and (2) DNS amplification attack mitigation.

In the context of this exercise, a heavy-hitter is defined as a flow exceeding a certain threshold, i.e., `hh_threshold`.
You will be given a packet trace which will be replayed to simulate live network traffic.
Elephant flows that are detected will be mirrored to an external collector.

The packets received at the collector will be compared against the groundtruth and graded.
Your implementation should capture all the heavy hitters and report them (i.e., the first packet that exceeds the `hh_threshold`) to the external collector.
Also, there should not be any duplicate reports.
For example, if there are three heavy flows `A`, `B`, and `C`, but if the collector received duplicate reports of `A`, `A`, `A`, we treat it as one heavy flow detected only.
We configure the collector such that it will only collect the first *n* packets.

The provided traces also contain some suspicious DNS traffic that are likely to be part of an DNS amplification attack.
A DNS amplification attack is a type of DDoS attack where an attacker exploits the functionality of open DNS servers to overwhelm a target system with a flood of DNS response traffic.
A victim of such an attack may receive a large volume of *unsolicited* DNS response packets, which can lead to network congestion, service disruption, and potential downtime.
For any DNS request-response pair, when the number of *unsolicited* DNS response packets exceeds a certain threshold, i.e., `drop_threshold`, we will consider this as a potential DNS amplification attack.
As such, we will drop all subsequent DNS response packets for that flow.

Note that you are expected to reuse your sketch implementation from Programming Assignment 2.
As such, you will need to make a copy of `libsketch_impl.so` from PA2 into the root directory of this exercise.

For this exercise, we provide you with two short packet traces under `sample-trace`.
In these short traces, as the counts are small and the number of flows are less, the expected error rates should be little to none.
This helps you to develop and validate your program with greater ease when comparing against the groundtruth.

That said, during grading, a (much) longer trace will be used.
In such cases, we allow an error rate of up to 10%.
For instance, if our threshold is at 100, we will account flows that have up to 110 packets as part of the hh flows from the groundtruth when evaluating your program as a true positive.

### Network Topology 

Below is the updated network topology for this exercise:

```
              +---------+        +-----------+        +---------+
              |  h1     |        |   s1      |        |   h2    |
              |10.0.0.1 |--------|           |--------|10.0.0.2 |
              +---------+   p1   |           |   p2   +---------+
                                 |           |
                                 +-----------+
                                       | p3
                                       |
                                 +---------+
                                 |   h3    |
                                 |10.0.0.3 |
                                 +---------+
```

| Host | IP Address      | MAC Address         | Remarks |
|------|----------------|---------------------|------------------------------------------------------------------------------|
| h1   | 10.0.0.1/24    | 08:00:00:00:01:11   | Can be sender/receiver of generated traffic |
| h2   | 10.0.0.2/24    | 08:00:00:00:02:22   | Can be sender/receiver of generated traffic |
| h3   | 10.0.0.3/24    | 08:00:00:00:02:22   | Collector host |

All hosts are connected to switch `s1` via ports `p1`, `p2`, and `p3` respectively.


### Requirements

The switch shall implement the following functionalities:
- Use your sketch implementation from PA2 to keep track of per-flow packet counts.
  - A flow is defined by the 5-tuple: (src IP, dst IP, src port, dst port, protocol).
- If a flow's packet count exceeds `hh_threshold`, mirror the packet to the collector host `h3` via port `p3`.
  - Only the first packet that exceeds the threshold should be mirrored.
  - Subsequent packets of the same flow should not be mirrored again.
- For any DNS request-response pairs, if the number of unsolicited DNS response packets exceeds `drop_threshold`, i.e., when `#responses > #requests`, drop all subsequent DNS response packets for that flow.

#### Sketch API

You are expected to reuse your sketch implementation from PA2, but only the following APIs are loaded and used for this exercise.
```C
...
Sketch* sketch_create();
uint32_t sketch_add_item(Sketch* es, const PacketFlow* flow);
uint32_t sketch_estimate_frequency(Sketch* es, const PacketFlow* flow);
...
```

## Step 1: Copy the Sketch Library

First, make a copy of the `libsketch_impl.so` from PA2 into the root directory of this exercise, i.e., it should be on the same directory as the `Makefile` and `monitoring.c`.

## Step 2: Run the (incomplete) starter code

The directory with this README also contains a skeleton DPDK program, `monitoring.c` which already implements end-to-end reachability between the hosts.
Your job will be to extend this skeleton program to detect heavy-hitters and drop suspicious DNS traffic.

Before that, let's compile the incomplete `monitoring.c` and bring up a switch in Mininet to test its behavior.
1. In your shell, run:
   ```bash
   make run
   ```
   This will:
   * compile `monitoring.c`, and
   * start the pod-topo in Mininet, and
   * configure all hosts with the commands listed in
   [pod-topo/topology.json](./pod-topo/topology.json)

2. Next, configure the `hh_threshold` and `drop_threshold` values.
We have provided a handy tool under `monitoring_util/` to help you set these threshold values.
To set the threshold values, run the following command in a new terminal:
```bash
# from the root directory of this exercise
# replace <hh_threshold> and <drop_threshold> with your desired values
$ sudo ./monitoring_util/monitoring_util -hht 50 -dt 100
``` 

> **Note:** The above sample threshold values (i.e., `hh_threshold`=50 and `drop_threshold`=100) are catered to the provided sample trace (`01-trace.csv`) found under `sample-trace/`. You can create your own traces for testing, and make sure to update the threshold values to fit your own trace.

Next, bring up three XTerm terminals for each hosts:
```bash
mininet> xterm h1 h2 h3
```

Before replaying the traces, we shall set up the collector at `h3`.
On `h3`, do the following:
```bash
# this is from h3's xterm terminal
root@p4# ./hh_collector.py 5
```
You can specify the number of reports that the collector should wait for.
The collector will print out a report at the end of the collection.

The provided sample traces currently have suspicious DNS response traffic destined towards `h2`.
We will do `tcpdump` on `h2` to observe these packets, and also to check if they are eventually dropped.
To observe these packets, do:
```bash
# this is from h2's xterm terminal
root@p4# tcpdump -i eth0 -n
```

Once `h2` and `h3` are ready, you can proceed to replay the traces.
To replay the traces, use the `generate_traffic.py` script.
You should do it from `h1`. 
An example are as follow:
```bash
# this is from h1's xterm terminal
root@p4# ./generate_traffic.py ./sample-trace/01-trace.csv
```
The `generate_traffic.py` script will print out a checkpoint for every 100 packet replayed.
Feel free to modify the script to suite your testing needs.

Your job is to extend this file so it can (1) detect and report the HH flows to the collector, and (2) also drop suspicious DNS response traffic.

> **Important!** As we currently have no way to clear the sketch, you should restart the Mininet instance if you want to replay the traces/generate new traffic so that you have a "fresh" sketch instance.

## Step 3: Implementation

The `monitoring.c` file contains a skeleton C program with key pieces of logic replaced by `TODO` comments.
Your implementation should follow the structure given in this file and replace the `TODO`s with logic implementing the missing piece.
You are allowed to add additional functions and include additional DPDK header files as needed, but you should not change the function signatures of the existing functions.

## Step 4: Run your solution

After implementing the sketch logic, you can run your solution by executing:
```bash
make run
```
This will compile your code and start the Mininet instance with your DPDK program.

> **Important!** Remember to set the threshold values and start the collector before replaying the trace or generating any traffic.

### Troubleshooting

There are several problems that might manifest as you develop your program:

1. `monitoring.c` might fail to compile. 
In this case, `make run` will report the error emitted from the compiler and halt.

2. `monitoring.c` might compile but it is not forwarding any traffic. 
The `logs/sX.log` files contain detailed logs that describing how your program processes each packet. 
You can add more logging statements in your code to help you debug the logic.
The output is detailed and can help pinpoint logic errors in your implementation. 
At the same time, you can also take a look at the PCAPs under `pcaps/`.

3. Make sure that the `monitoring` process is running in the background.
You can check this by running: `ps aux | grep monitoring`.
If you do not see the process, it means that the DPDK software switch may have exited unexpectedly.
If this is the case, you can check the `logs/sX.log` files for any error messages that may have caused the exit.
Alternatively, make sure that you do not have any `return` statements in the main loop of your program, as this will cause the program to exit prematurely.

#### Cleaning up Mininet

In the latter two cases above, `make run` may leave a Mininet instance running in the background. 
Use the following command to clean up these instances:

```bash
make stop
```

## Running the Packet Test Framework (PTF)

We will be grading your using the Packet Test Framework (PTF), which allows us to specify test cases with different input/output packets to verify your DPDK data plane program behavior.
This is inline with modern software engineering practices.

We have provided some public test cases that you can use to quickly test your program.
For that, simply do `./runptf.sh`.

Note that passing all the public test cases do not necessarily mean that you will get full marks for the exercise as there are other hidden test cases that will be used during grading.
In addition, not all public test cases will be scored as some are purely for sanity check.
