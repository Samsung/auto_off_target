AoT makes it possible for user to take control over data initialization process.

This is done via a special JSON file in which the user can specify how parameters of a given function are going to be initialized.

NOTE: currently the data init file supports only function arguments but it should be failry easy to add globals in a similar way. Only simple types are supported right now, so for example it is not possible to define a member of a struct to be of size "x" - it should also be possible to add that type of init (contributions welcome!).
UPDATE IN NOTE: Now it is possible to define a member of a struct!


The file has the following format:
```
[
  {
    "name": <func/type/global name>,
    "order": [
      <id1>,
      <id3>,
      ...
      <idN>
    ],
    "items": [
      {
        "id": <number>,
        "name": <item name>,
        "size": <item size - for pointers that's the array size>
        "size_dep": {
          "id": <number>,
          "add": <number>
        },
        "user_name": <name>,
        "value": <number>,
        "value_dep": [
          <string 1>,
          <string 2>,
          ...
          <string n>
        ],
        "min_value": <number>,
        "max_value": <number>,
        "nullterminated": ["True"|"False"],
        "tagged": ["True"|"False"],
        "fuzz": ["True"|"False"],
        "fuzz_offset": <number>,
        "subitems": [
          {
            "id": <number>,
            "name": <item name>,
            ...
          },
          {
            "id": <number>,
            "name": <item name>,
            ...
          },
          ...,
          {
            "id": <number>,
            "name": <item name>,
            ...
          }
        ]
      }
      ...
    ]
  },
  ...
]
```

Let's analyze the format on a concrete example
```
[
  {
    "name": "foo_store",// name: name of a function we are looking at
    "order": [          // order: initialization order: the parameter with id 0 should be initialized 
      1,                //                              after the parameter with id 1
      0
    ],
    "items": [          // items: a list of parameters we care about
      {
        "id": 0,        // id: an id of a paramter used to uniquely identify it
        "name": [       // name: a list of possible parameter names (as found in various definitions)
          "buf",        //       this is useful when automating init file creation for a class of functions 
          "page",       //       with a common API
          "b",
          "buff",
          "data",
          "ubuf",
          "arg"
        ],
        "size": 4097,   // size: the size of a buffer (used for pointer/array arguments)
        "size_dep": {   // size_dep: the size is dependent on the parameter with id 1; it means that if we find
          "id": 1,      //           the parameter with id 1 the buffer size will be equal to the value of that 
          "add": 0      //           paramter + the number in the "add" field (otherwise we fallback to "size")
        },
        "nullterminated": "False", // nullterminated: should the buffer be null-terminated?
        "tagged": "True",          // tagged: should we assing a tag/taint to the buffer?
        "fuzz": "False"            // fuzz: should be fuzz the buffer?
      },
      { // skipping the descriptions of the already described fields
        "id": 1,
        "name": [
          "size",
          "count",
          "len",
          "n",
          "length"
        ],
        "user_name": "count", // user_name: the parameter's name will be changed to the user-provided string
        "value": 4096,        // value: the value of the paramters (useful for integral params) - used when the parameter is not fuzzed (e.g. for KLEE)
        "min_value": 1,       // min_value: a minimum value the parameter can take (useful when the fuzzing is on)
        "max_value": 4096,    // max_value: a maximum value the parameter can take (useful whrn the fuzzing is on)
        "tagged": "True"
      }
    ]
  }
]
```

Moreover, you can see these initialization data file members
```
{
  ...
  "value_dep": [                            // value_dep: the value is dependent on the value of ((struct nlmsghdr *)name_of_function_argument->data)->nlmsg_len
      "(((struct nlmsghdr *)",              //            after some calculations; it means that after allocating memory for this variable we then set its value
      "->data)->nlmsg_len + 19) & ~(3)"     //            to the calculated result of expression made by concatenation of given strings and name of function argument
  ],
  ...
}
...
{
  ...
  "subitems": [                             // subitems: our way of defining initialization data for selected members of structs; the format of subitems is
      {                                     // the same as items' format
          "id": 3,
          "name": [
              "nlmsg_len"
          ],
          "user_name": "nlmsg_len",
          "value": 3712,
          "min_value": 0,
          "max_value": 3712,
          "tagged": "True"
      },
      {
          "id": 4,
          "name": [],
          "size": 3696,
          "size_dep": {
              "id": 3,
              "add": 0
          },
          "nullterminated": "False",
          "tagged": "True",
          "fuzz": "True",
          "fuzz_offset": 16     // fuzz_offset: offset from the beginning of struct in case when the member is unnamed (for example unnamed payload after header)
      }
  ],
  ...
}
```

Our file defines how AoT should behave when generating initialization for arguments of the ```foo_store``` function.
The function has 2 parameters we care about, which are defined in the "items" list. We also note that the arguments init should be reordered: this is defined in the "order" table in which we state that the argument represented by id 1 should be initialized before the argument represented by id 0. This is useful when we have an array and array size - in those cases we wish to initialize or fuzz the array size first and then create the array of the specified size. 

The way arguments are defined is sort of fuzzy. The function ```foo_store``` does not necessarily have 2 arguments. In fact it should have _at least_ two. How do we know which arguments we reference? Inside each member of the "items" table we have the "name" table. That table contains a list of possible names that the given argument might take in the code. Why is that a list? Function's definition should have a single argument name! 
The list is there in order to make the automation easier: let's assume we have a class of functions with similar API to ```foo_store```. All of them have some argument representing a buffer and another one representing the buffer size. However, sometimes the buffer is called "buf", another time "buff", similarly for the size: "count", "length", etc. By having a list it's easier to automatically generate the init file for a whole class of functions. 

In a summary, we are looking for a function named ```foo_store``` and wish to have a special initialization (with special order) of two of its arguments: a buffer and the buffer size. Please find the detailed breakdown of the data file fields in the comments.
You might have noticed that while we have the "fuzz" field defined for the buffer we miss that for the count. This is because in AoT simple builtin types such as ```int``` are fuzzed by default.

Curious to see what type of init comes out of the example JSON file mentioned above?
```c
    ...
    size_t count; // note that we call the parameter "count" (field user_name) and initialize it before "buf" (field order)
 
    aot_memory_init(&count, sizeof(unsigned long), 1 /* fuzz */, 0); // "count" is fuzzed as it's a simple type (size_t is unsigned long)
    aot_tag_memory(&count, 0); // we wanted to tag the "count" parameter (field tagged)

#ifdef KLEE
    if (argc == 1) // a special case for KLEE: we set the parameter to a concrete value (field value)
      count = 4096;
#endif

    if (count < 1) // field min_value
      count = 1;
    if (count > 4096) // field max_value
      count = 4096;

    char *buf;
    aot_memory_init_ptr((void**) &buf, sizeof(char), count + 1 /* count */, 1 /* fuzz */, // please note that we use "count" as the size (field size_dep)
                        0);

    buf[count + 1 - 1] = 0; // field nullterminated

    aot_tag_memory(buf, 0); // field tagged
    // didn't find any deeper use of buf

    ret_value = foo_store(param1, param2, buf, count); // the order of params is different to the order of init
```

For the details on the AoT API functions ```aot_*``` please see docs/aot_libs.md

The data init JSON file can be generated by hand but you could also automate that process.
