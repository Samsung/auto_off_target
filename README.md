# AoT: Auto off-Target
Automatically generating off-target test harness by using build information.

Brought to you by the Mobile Security Team at Samsung R&D Warsaw, Poland.

# Overview
Imagine you could pick up a fragment of code in a complex system written in C and test it in separation on your Linux workstation without the burden of including all necessary headers and knowing the right set of #defines, compilation flags and the target architecture. Imagine you could use that code in a modern fuzzer or symbolic execution engine for thorough, focused deep testing. 

AoT makes it possible to select a function from C code base and generate an executable off-target test harness. The harness can then be tested on a Linux machine, e.g. with ASAN, AFL or KLEE. The generated off-target is a self-contained binary and includes all the necessary types and definitions. 
In a nutshell, AoT makes it possible to test pieces of complex systems software in a unit test-like manner. 

# What it is and how does this work?
First, you select a function F you are interested to test. AoT uses Code Aware Services (CAS) infrastructure, namely code database and build information database to automatically pull in a subtree of functions called by F (that is, functions that F calls, functions that they call, etc.). By default, AoT stops at the module boundary: the functions compiled into the same module as F are pulled in, all the others are left out. For the functions that are left out AoT generates function stubs which can later be filled by the user. 
Such generated program is called an off-target, because it runs off the original code execution environment (e.g. a smartphone).

AoT works well with the AFL (https://lcamtuf.coredump.cx/afl/) and AFL++ (https://github.com/AFLplusplus/AFLplusplus) fuzzers and KLEE symbolic execution engine (http://klee.github.io/). It automatically generates binaries and test setup for those tools, so that you can start fuzzing the off-target immediately. 

AoT is an automated solution that currently works in the human-in-the-loop model. It means that AoT tries to automate as much as possible, but a human operator is needed to fine-tune the results - e.g. provide stubs implementation or correct the program state initialization.

Potential uses of AoT are:
  - get a recursive list of functions given an entry point (could be used to get selective coverage)
  - get a list of types necessary for a given piece of code
  - instrument code for intra-structure fuzzing (unsupported yet)
  - instrument code for fuzzing / symbolic execution and apply those techiques to complex systems code
  - speed up development for slowly building targets

For example, let's imagine we would like to test a message parser in a mobile phone modem. Normally, for such testing we need to set up the physical infrastructure, i.e., a base station that sends messages over the air to the mobile phone. When the message is received by the phone, the parser code is invoked. If there is an error, we need to collect potential crash logs (if any) and restart testing. 
The whole process is difficult to set up and a single testing cycle takes quite long.
With AoT things look differently. We select the message parsing function as our target. AoT automatically pulls in the necessary definitions and functions compiled into the same module and generates function stubs for the functions outside of the module. Moreover, AoT generates the program state initialization and the code necessary to start security fuzzing. 
The generated off-target code is self contained - we can compile it on a Linux box and use all standard tools such as fuzzers, gdb, sanitizers to test the code.
As a result, we end up with a much faster setup and a shorter test cycle: the off-target generation takes minutes and we can re-execute the code up to thousands of times per minute. We can also easily attach a debugger and quickly inspect what went wrong.

As a further example let's take the last point and let's imagine we are modifying an AOSP kernel driver. 
Without AoT, we need to invoke entire build process to check if our change is correct. Moreover, we would need to run the 
code in an Android emulator or on the phone and find a way to invoke the changed driver code (which sometimes is not trivial). 
With AoT, we can quickly extract the code of the changed function and compile it. 
We can further use all available x86_64 Linux toolchains (gdb, sanitizers, etc.) to test it. As a result, the development & testing cycle should be much shorter.  

# Wait, can't I use virtualization?

In the ideal scenario we could emulate the entire target system, however in practice there are no emulators for complex custom CPUs such as Snapdragon, Exynos, Hexagon, etc. (not to mention custom IoT hardware). Developing and maintaining an emulator is not an easy task and could take a lot of time. On the other hand, there are valid use cases in which you in fact don't need the emulation of an entire hardware platform - if you wish to test message parser in the modem, you do not need to emulate an entire modem.

# What AoT cannot do?

Currently, AoT is not able to translate architecture-specific assembly code. As a result, each function containing assembly is automatically treated as external and stubbed out (though the user can change that default behaviour).

Moreover, as of now, AoT supports C language only (C++ is in progress).

# Prerequisites

* AoT is a source-based white box solution. It means that you need to be able to build your target system's source code in order to use AoT.

* In order to run AoT you need to have CAS databases (db.json, nfsdb.json) available for the target system. The creation of the database is beyond the scope of AoT, in a nutshell CAS happens during the build process. Please check the CAS (https://github.com/Samsung/CAS) project for more details.

* Technical:
  * Python3
  * a bunch of packages listed in requirements.txt

# That all sounds great, how do I start?

## 0) Clone this repo! 
    
Let's assume we would like to generate an off-target code for the ```parse_args``` function of the AOSP Linux kernel. This function is responsible for parsing argument string provided by the user during the kernel bootup process.

First, we clone the repo and prepare some files we will need in the next steps. ```CAS_DIR``` is the main directory for CAS (see the example in CAS repo for creating the databases).

```
git clone https://github.com/Samsung/auto_off_target.git && cd auto_off_target
export AOT_DIR=$(pwd)
cd ${CAS_DIR}/avdkernel
echo "{ \"BASserver\": \"https://localhost\" }" > cfg.json
cp ${AOT_DIR}/src/known_functions .
cp ${AOT_DIR}/src/lib_functions .
cp ${AOT_DIR}/src/always_include .
```

Let's create a data init file for our function and store it as ```init.json```. This file will cause AoT to allocate 4096 bytes for the ```args``` parameter, null-terminate the buffer and mark it fuzzable. 

```
[
  {
    "name": "parse_args",
    "interface": "store",
    "items": [
      {
        "id": 0,
        "name": [
          "args"
        ],
        "size": 4096,
        "nullterminated": "True",
        "tagged": "True",
        "fuzz": "True"
      }
    ]
  }
]
```
    
## 1) [Once per product build only] Import CAS databases into AoT. 
    
```aot.py --config=cfg.json --product=linux-kernel-common --version=5.10-66 --build-type=eng --import-json=db.json --rdm-file=rdm.json --known-funcs-file=known_functions --lib-funcs-file=lib_functions --always-inc-funcs-file=always_include --init-file=init.json --source-root=${CAS_DIR}/avdkernel/kernel```


Let's break down the arguments:

* ```aot.py``` : our main script; you can find it under the ```src``` dir of this repo

* ```--config=cfg.json``` : a configuration json file.
An example config file looks like this:
```
{
  "BASserver": "https://localhost"
}
```

* ```--product=linux-kernel-common --version=5.10-66 --build-type=eng``` : product, version and build-type is a triple that uniquely identifies the build we are interested in; as we shall see later, the same triple is used when generating off-targets (under the hood, the triple is used to connect to the right database instance)

* ```--import-json=db.json --rdm-file=rdm.json``` : these options select CAS database JSON files to import - ```db.json``` is the code database, ```rdm.json``` is a part of compilation database; both files are provided by the CAS infrastructure; NOTE: the ```db.json``` file needs to be a special version of code database prepared for AoT - ask your CAS provider about which file to use 

* ```--known-funcs-file=known_functions``` : there are some functions which we would like to treat as known - if a function of the same name is detected in the off-target, it's body _will not_ be imported; the ```known_functions``` file provides a list of known function names; you can find the default file under ```src/known_functions```

* ```--lib-funcs-file=lib_functions``` : AoT makes it possible to provide your own implementation for certain functions; these user-provided implementations are stored in ```src/resources/aot_lib.c```; in the ```lib_funcs_file``` argument we specify a file which provides a list of names of the user-provided library functions; you can find the default file under ```src/lib_functions```

* ```--always-inc-funcs-file=always_include``` : AoT makes it possible to specify a list of functions that will always be included in the generated code whenever they are encountered, regardless of the cut-off algorithm used; the  ```always_include``` file provides a list of function names; you can find the default file under ```src/always_include``` 

* ```--init-file=init.json``` : AoT makes it possible to introduce constraints on the data sent to our target function(s); this is performed via a special JSON file
For more information on init files see: docs/data_init_file.md.

* ```--source-root=/path```: with this optional argument you can specify the root directory of the build (please ask your CAS provider on how to find it); this can help if the code database (db.json) contains relative paths

NOTE: you can safely use ```known_functions```, ```lib_functions``` and ```always_include``` files provided in the ```src``` dir. Don't worry if you don't have the init file right now, you still will be able to perform the database import with a file containing just ```[]```.

The first point should ideally be done as a part of the build process as it only need to be performed _once per product build_. This involves setting up the CAS infrastructure which is beyond the scope of this intro.
  
## 2) After importing the database, you can generate your first off-target with AoT. 

```aot.py --config=cfg.json --product=linux-kernel-common --version=5.10-66 --build-type=eng --db=db.img --output-dir out_dir --functions parse_args --external-inclusion-margin 1 --init --verify-struct-layout```

Let's break down the arguments:

* ```aot.py --config=cfg.json --product=linux-kernel-common --version=5.10-66 --build-type=eng``` : these are exactly the same as previously - we provide the same config file and we specify the build we are interested in via the {product, version, build-type} triple

* ```--db=db.img``` : this is a db file created during the import step

* ```--output-dir out_dir``` : this is the directory in which the off-target will be generated

* ```--functions parse_args``` : the ```functions``` parameter makes it possible to specify the names of functions for which we wish to generate the off-target code; NOTE: if the name of a function occurs in more than one file, it's possible to specify the file via the ```function_name@file_name``` syntax (AoT will let you know about that in a log message)

* ```--external-inclusion-margin 1``` : AoT extracts just a part of the original system - by default that is a recursive subtree of functions called by user-specified functions which are included in the same compiled module; as a result every first function outside of the module is left out as a function stub; however, there are cases in which we call a function that is outside of our current off-target but that function doesn't call any other functions - in those cases it doesn't make much sense to leave these functions out as they might be useful in our off-target code (and we won't need to provide stubs for them); the ```---external-inclusion-margin``` function is a parameter that allows you to add some of the otherwise external functions - the number you provide means that the included function needs to call less than the number of other functions (1 means that the function doesn't call other functions at all)

* ```--init``` : tell AoT to perform a smart initialization of function parameters; without this parameter, our target functions will have all the necessary arguments, but they won't be initialized - this almost certainly mean that the code would be incorrect and will need to be fixed manually;

* ```--verify-struct-layout``` : tell AoT to add verification code which checks whether the layout of generated struct types is exactly the same as it was on the original target (this option is optional). To run the verification add `--verify-struct-layout` option to the compiled binary when run.

Now you wait a couple of minutes and if everything goes all right you can find the off-target code in the output directory.

Let's take a quick look at the directory contents:
* The source files that start with the ```aot_*``` prefix come from the AoT library. 
* The ```aot.c``` file is the main file of the off-target code: it contains the main() function and calls to all the functions we target.
* The ```aot.h``` is the main header file; for simplicity AoT generates a single header file that contains all the necessary definitions; name clashes are resolved via automatically generated #ifdef clauses.
* The source files named ```file_<NUMBER>.c``` are representing real code structure in the original code: the number is a unique identifier of the original file; those files contain globals and definitions of the included functions.
* The source files named ```file_stub_<NUMBER>.c``` contain function stubs for the functions that didn't make it to the off-target code base; just like for the previously discussed files, the number denotes a unique identifier of the original function's file.
* ```build.sh``` : build the off-target; this creates binaries for native x86_64, debugging, getting coverage, address sanitizer, undefined behavior sanitizer, DFSAN, AFL and KLEE

NOTE: You will notice that the source code of the generated functions is somewhat different to the original. This is because AoT operates on a _post-processed_ code, that is after the compiler parser resolves all #define statements and macros. On one hand this might be a bit harder to read, on the other hand this is _exactly_ the code that is being compiled.

## 3) Fuzz, test & debug
 
Once the off-target is up and running you can use it for fuzzing, testing, debugging, symbolic execution or faster compilation. 


# Last but not least

If you find AoT useful we would greatly appreciate it if you could give us a credit :)

We would love to see a growing community around AoT! Feel free to file issues, propose new ideas, implement new features, fix bugs, refactor code, etc.

If you work on a fork of this project and modify the code, we highly recommend merging your changes back to the main project.
Not only would that benefit the user community around AoT but also it would prevent a situation in which multiple unsynchronized versions of AoT exist at the same time with varying sets of features.

Thank you and have fun!
