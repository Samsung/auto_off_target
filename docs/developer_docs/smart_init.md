One of the most common issues with data init are cases in which we have a struct
which contains a pointer and its size. In order for init to be correct we have to 
a) use the size member when allocating the pointer
b) limit the value of the size member

A lot of information can be extracted statically from db.json.
The ```_generate_member_size_info``` function in AoT performs the extraction process.
The function populates the member_usage_info structure. 
The structure is a dict in which type ids are the keys. 
The values are arrays of the length corresponding to the number of members in a structure.
Each member of that array is a dict with the following structure:

```
{ "value" : int, 
  "member_idx" :  [ list ], // a list of pairs <type id, member index inside the type>
  "member_size" : [ list ], // a list of pairs <type id, member index inside the type>
  "name_size : [ list ],    // a list of member indices
  "index" : int,
}
```

The keys are present only if the corresponding data is found.
All the keys except for "index" relate to a pointer-type members (buffers).
The "index" key relates to int-like members (buffer indices).

Please find an example of how the dictionary values are generated, depening on 
the information extracted from the db.json.

```
struct A{
char *word;
int len;
}
 
struct B{
struct *A;
int alen;
}
 
struct C{
int *data;
int data_len;
}
 
struct D{
int array[20];
int idx;
}
```

1) value:
```
A a;
a.word[20] = '\0';  //add 1 to value
a.word[24] = '\0'; //add 1 to value
int idx;
if(idx<32) a.word[idx] = 'a' //don't add 1
if(idx<=40) a.word[idx]='b' //add 1
for(;idx!=10;) a.word[idx] ='c'//don't add 1
```
For member "word" in A:
"value" max(21,25,32,41,10)

2) member_idx:
```
A a;
B b;
a.word[a.len] = 0;
a.word[b.alen] = 0;
```
For member "word" in type A:
{ "member_idx" : [(0,1),(1,1)]  ------------ [(idA,refid_len),(idB,refid_alen)] }
 
3) member_size:
```
A a;
B b;
int idx;
if(idx<a.len) a.word[idx] = '\0'
for(;idx<b.alen;) a.word[idx] = '\0'
```
For member "word" in type A:
"member_size" : [(0,1),(1,1)]  ------------ [(idA,refid_len),(idB,refid_alen)]
 
4) name_size:
For member "data" in type C:
"name_size" : [1]
 
5) index:
```
D d;
int local_array[30];
d.array[d.idx] = 0;
local_array[d.idx] = 0
```
For member "idx" in type D:
"index" : max(20,30)
