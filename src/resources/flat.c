/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 


#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <sys/time.h>
#include <limits.h>
#include <stddef.h>

#ifdef __linux__
  #define _ALIGNAS(n)	__attribute__((aligned(n)))
  #define RB_NODE_ALIGN	(sizeof(long))
#else
#ifdef _WIN32
  #define _ALIGNAS(n)	__declspec(align(n))
  #ifdef _M_IX86
    #define RB_NODE_ALIGN	4
  #elif defined _M_X64
    #define RB_NODE_ALIGN	8
  #endif
#endif	/* _WIN32 */
#endif /* __linux__ */

#ifdef __linux__
  #include <alloca.h>
  #define ALLOCA(x)	alloca(x)
#else
  #ifdef _WIN32
    #include <malloc.h>
    #define ALLOCA(x)	_malloca(x)
  #endif
#endif

#ifdef __linux__
  #define container_of(ptr, type, member) ({			\
  	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
  	(type *)( (char *)__mptr - offsetof(type,member) );})
#else
  #ifdef _WIN32
    #define container_of(ptr, type, member) (type *)( (char *)(ptr) - offsetof(type,member) )
  #endif
#endif

struct _ALIGNAS(RB_NODE_ALIGN) rb_node {
	uintptr_t  __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};
/* The alignment might seem pointless, but allegedly CRIS needs it */

struct rb_root {
	struct rb_node *rb_node;
};

struct interval_tree_node {
	struct rb_node rb;
	uintptr_t start;	/* Start of interval */
	uintptr_t last;	/* Last location _in_ interval */
	uintptr_t __subtree_last;
	void* mptr;
};

#include "interval_tree.h"
#include "interval_tree_generic.h"

#define START(node) ((node)->start)
#define LAST(node)  ((node)->last)

void __rb_erase_color(struct rb_node *parent, struct rb_root *root,
		void (*augment_rotate)(struct rb_node *old, struct rb_node *__new));
void __rb_insert_augmented(struct rb_node *node, struct rb_root *root,
		void (*augment_rotate)(struct rb_node *old, struct rb_node *__new));

INTERVAL_TREE_DEFINE(struct interval_tree_node, rb,
		     uintptr_t, __subtree_last,
		     START, LAST,, interval_tree)

void* malloc (size_t size);
void* calloc (size_t num, size_t size);
void free(void *ptr);

struct interval_tree_node * interval_tree_iter_first(struct rb_root *root, uintptr_t start, uintptr_t last);
struct interval_tree_node *	interval_tree_iter_next(struct interval_tree_node *node, uintptr_t start, uintptr_t last);
struct rb_node* interval_tree_insert(struct interval_tree_node *node, struct rb_root *root);

#define TIME_MARK_START(start_marker)		\
		struct timeval  tv_mark_##start_marker;	\
		gettimeofday(&tv_mark_##start_marker, 0)

#define TIME_CHECK_FMT(start_marker,end_marker,fmt)	do {	\
		struct timeval  tv_mark_##start_marker##_##end_marker;	\
		gettimeofday(&tv_mark_##start_marker##_##end_marker, 0);	\
		printf(fmt,	\
		(double) (tv_mark_##start_marker##_##end_marker.tv_usec - tv_mark_##start_marker.tv_usec) / 1000000 +	\
		         (double) (tv_mark_##start_marker##_##end_marker.tv_sec - tv_mark_##start_marker.tv_sec) );	\
	} while(0)

struct flatten_header {
	size_t memory_size;
	size_t ptr_count;
	size_t fptr_count;
	size_t root_addr_count;
	size_t root_addr_extended_count;
	size_t root_addr_extended_size;
	uintptr_t this_addr;
	size_t fptrmapsz;
	size_t mcount;
	uint64_t magic;
};

enum flatten_option {
	option_silent = 0x01
};

struct blstream {
	struct blstream* next;
	struct blstream* prev;
	void* data;
	size_t size;
	size_t index;
	size_t alignment;
};


/* Root address list */
struct root_addrnode {
	struct root_addrnode* next;
	uintptr_t root_addr;
};

struct FLCONTROL {
	struct blstream* bhead;
	struct blstream* btail;
	struct rb_root fixup_set_root;
	struct rb_root imap_root;
	struct flatten_header	HDR;
	struct root_addrnode* rhead;
	struct root_addrnode* rtail;
	struct root_addrnode* last_accessed_root;
	int debug_flag;
	unsigned long option;
	void* mem;
};

#define RB_ROOT	{ 0, }

struct FLCONTROL FLCTRL = {
		.bhead = 0,
		.btail = 0,
		.fixup_set_root = RB_ROOT,
		.imap_root = RB_ROOT,
		.rhead = 0,
		.rtail = 0,
		.last_accessed_root=0,
		.debug_flag=0,
		.option=0,
		.mem = 0,
};

#define FLATTEN_MAGIC 0x464c415454454e00ULL

#define ROOT_POINTER_NEXT(PTRTYPE)	((PTRTYPE)(root_pointer_next()))
#define ROOT_POINTER_SEQ(PTRTYPE,n)	((PTRTYPE)(root_pointer_seq(n)))
#define FLATTEN_MEMORY_START	((unsigned char*)FLCTRL.mem+FLCTRL.HDR.ptr_count*sizeof(size_t)+FLCTRL.HDR.fptr_count*sizeof(size_t)+FLCTRL.HDR.mcount*2*sizeof(size_t))

struct rb_root fptrmap = RB_ROOT;

struct fptrmap_node {
	struct rb_node node;
	uintptr_t v;
	const char* f;
};

struct fptrmap_node* fptrmap_search(uintptr_t v) {

	struct rb_node *node = fptrmap.rb_node;

	while (node) {
		struct fptrmap_node* data = container_of(node, struct fptrmap_node, node);

		if (v<data->v) {
			node = node->rb_left;
		}
		else if (v>data->v) {
			node = node->rb_right;
		}
		else
			return data;
	}

	return 0;
}

int fptrmap_insert(uintptr_t v, const char* f, size_t sz) {

	struct fptrmap_node* data = calloc(1,sizeof(struct fptrmap_node));
	struct rb_node **new, *parent = 0;
	data->v = v;
	data->f = strndup(f,sz);
	new = &(fptrmap.rb_node);

	/* Figure out where to put new node */
	while (*new) {
		struct fptrmap_node* this = container_of(*new, struct fptrmap_node, node);

		parent = *new;
		if (data->v<this->v)
			new = &((*new)->rb_left);
		else if (data->v>this->v)
			new = &((*new)->rb_right);
		else {
			free((void*)data->f);
		    free(data);
		    return 0;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node_internal(&data->node, parent, new);
	rb_insert_color_internal(&data->node, &fptrmap);

	return 1;
}

int fptrmap_delete(uintptr_t v) {

	struct fptrmap_node* node = fptrmap_search(v);
	if (node) {
		rb_erase(&node->node, &fptrmap);
		return 1;
	}
	return 0;
}

void fptrmap_destroy(void) {

	struct rb_root* root = &fptrmap;
	struct rb_node * p = rb_first(root);
    while(p) {
        struct fptrmap_node* data = (struct fptrmap_node*)p;
        rb_erase(p, root);
        p = rb_next(p);
        free((void*)data->f);
        free(data);
    }
}

size_t recipe_count(void) {

	struct rb_root* root = &fptrmap;
	struct rb_node * p = rb_first(root);
	size_t count = 0;
	while(p) {
		count++;
		p = rb_next(p);
	}
	return count;
}

void* root_pointer_next() {

	assert(FLCTRL.rhead!=0);

	if (FLCTRL.last_accessed_root==0) {
		FLCTRL.last_accessed_root = FLCTRL.rhead;
	}
	else {
		if (FLCTRL.last_accessed_root->next) {
			FLCTRL.last_accessed_root = FLCTRL.last_accessed_root->next;
		}
		else {
			assert(0);
		}
	}

	if (FLCTRL.last_accessed_root->root_addr==(size_t)-1) {
		return 0;
	}
	else {
		if (interval_tree_iter_first(&FLCTRL.imap_root,0,ULONG_MAX)) {	/* We have allocated each memory fragment individually */
			struct interval_tree_node *node = interval_tree_iter_first(&FLCTRL.imap_root,FLCTRL.last_accessed_root->root_addr,FLCTRL.last_accessed_root->root_addr+8);
			assert(node);
			size_t node_offset = FLCTRL.last_accessed_root->root_addr-node->start;
			return (unsigned char*)node->mptr+node_offset;
		}
		else {
			return (FLATTEN_MEMORY_START+FLCTRL.last_accessed_root->root_addr);
		}
	}
}

void* root_pointer_seq(size_t index) {

	assert(FLCTRL.rhead!=0);

	FLCTRL.last_accessed_root = FLCTRL.rhead;

	size_t i=0;
	for (i=0; i<index; ++i) {
		if (FLCTRL.last_accessed_root->next) {
			FLCTRL.last_accessed_root = FLCTRL.last_accessed_root->next;
		}
		else {
			assert(0);
		}
	}

	if (FLCTRL.last_accessed_root->root_addr==(size_t)-1) {
		return 0;
	}
	else {
		if (interval_tree_iter_first(&FLCTRL.imap_root,0,ULONG_MAX)) {	/* We have allocated each memory fragment individually */
			struct interval_tree_node *node = interval_tree_iter_first(&FLCTRL.imap_root,FLCTRL.last_accessed_root->root_addr,FLCTRL.last_accessed_root->root_addr+8);
			assert(node);
			size_t node_offset = FLCTRL.last_accessed_root->root_addr-node->start;
			return (unsigned char*)node->mptr+node_offset;
		}
		else {
			return (FLATTEN_MEMORY_START+FLCTRL.last_accessed_root->root_addr);
		}
	}
}

void root_addr_append(uintptr_t root_addr) {
    struct root_addrnode* v = (struct root_addrnode*)calloc(1,sizeof(struct root_addrnode));
    assert(v!=0);
    v->root_addr = root_addr;
    if (!FLCTRL.rhead) {
        FLCTRL.rhead = v;
        FLCTRL.rtail = v;
    }
    else {
        FLCTRL.rtail->next = v;
        FLCTRL.rtail = FLCTRL.rtail->next;
    }
}

void fix_unflatten_memory(struct flatten_header* hdr, void* memory) {
	size_t i;
	void* mem = (unsigned char*)memory+hdr->ptr_count*sizeof(size_t)+hdr->fptr_count*sizeof(size_t)+hdr->mcount*2*sizeof(size_t);
	for (i=0; i<hdr->ptr_count; ++i) {
		size_t fix_loc = *((size_t*)memory+i);
		uintptr_t ptr = (uintptr_t)( *((void**)((unsigned char*)mem+fix_loc)) );
		/* Make the fix */
		*((void**)((unsigned char*)mem+fix_loc)) = (unsigned char*)mem + ptr;
	}
}


typedef uintptr_t (*get_function_address_t)(const char* fsym);

void unflatten_init() {
}

typedef int (*fptrstub_t)(void);

struct fptrstub_node {
	struct rb_node node;
	const char* s;
	fptrstub_t address;
};

struct triggerstub_node {
	struct rb_node node;
	const char* s;
	size_t index;
	size_t size;
};

extern struct rb_root triggerstubset_root;

void initialize_function_pointer_stubs(void);
void initialize_fptrstubset(void);
void aot_kflat_initialize_global_variables(void);

struct fptrstub_node* fptrstubset_search(const char* s);
int fptrstubset_insert(const char* s, fptrstub_t address);
void fptrstubset_destroy(struct rb_root* root);
size_t fptrstubset_count(const struct rb_root* root);

struct triggerstub_node* triggerstubset_search(const char* s);
int triggerstubset_insert(const char* s, size_t index, size_t size);
void triggerstubset_destroy(struct rb_root* root);
size_t triggerstubset_count(const struct rb_root* root);

int unflatten_create(FILE* f, get_function_address_t gfa) {

	TIME_MARK_START(unfl_b);
	size_t readin = 0;
	size_t rd = fread(&FLCTRL.HDR,sizeof(struct flatten_header),1,f);
	printf("--- Read image header: %zu [B]\n",sizeof(struct flatten_header));
	printf("---   Memory size                 : %zu\n",FLCTRL.HDR.memory_size);
	printf("---   Pointer count               : %zu\n",FLCTRL.HDR.ptr_count);
	printf("---   Function pointer count      : %zu\n",FLCTRL.HDR.fptr_count);
	printf("---   Root address count          : %zu\n",FLCTRL.HDR.root_addr_count);
	printf("---   Root address extended count : %zu\n",FLCTRL.HDR.root_addr_extended_count);
	printf("---   Root address extended size  : %zu\n",FLCTRL.HDR.root_addr_extended_size);
	printf("---   Base address                : %lx\n",FLCTRL.HDR.this_addr);
	printf("---   Function pointer map size   : %zu\n",FLCTRL.HDR.fptrmapsz);
	printf("---   Memory fragment count       : %zu\n",FLCTRL.HDR.mcount);
	if (rd!=1) return -1; else readin+=sizeof(struct flatten_header);
	if (FLCTRL.HDR.magic!=FLATTEN_MAGIC) {
		fprintf(stderr,"Invalid magic while reading flattened image\n");
		return -1;
	}
	printf("--- Root address array offset: 0x%lx\n",sizeof(size_t)+sizeof(struct flatten_header));
	size_t* root_addr_array = (size_t*)malloc(FLCTRL.HDR.root_addr_count*sizeof(size_t));
	assert(root_addr_array);
	rd = fread(root_addr_array,sizeof(size_t),FLCTRL.HDR.root_addr_count,f);
	if (rd!=FLCTRL.HDR.root_addr_count) return -1; else readin+=sizeof(size_t)*FLCTRL.HDR.root_addr_count;
	unsigned char* root_addr_extended_data = (unsigned char*)malloc(FLCTRL.HDR.root_addr_extended_size);
	assert(root_addr_extended_data);
	rd = fread(root_addr_extended_data,1,FLCTRL.HDR.root_addr_extended_size,f);
	if (rd!=FLCTRL.HDR.root_addr_extended_size) return -1; else readin+=FLCTRL.HDR.root_addr_extended_size;
	unsigned char* p = root_addr_extended_data;
	for (size_t i=0; i<FLCTRL.HDR.root_addr_extended_count; ++i) {
		size_t name_size = *((size_t*)p);
		p+=sizeof(size_t);
		const char* name = strndup((const char*)p,name_size);
		p+=name_size;
		size_t index = *((size_t*)p);
		p+=sizeof(size_t);
		size_t size = *((size_t*)p);
		p+=sizeof(size_t);
		triggerstubset_insert(name,index,size);
	}
	assert(root_addr_extended_data+FLCTRL.HDR.root_addr_extended_size==p);
	printf("--- Pointer array offset: 0x%lx\n",sizeof(size_t)+sizeof(struct flatten_header)+
			FLCTRL.HDR.root_addr_count*sizeof(size_t)+FLCTRL.HDR.root_addr_extended_size);
	printf("--- Function pointer array offset: 0x%lx\n",sizeof(size_t)+sizeof(struct flatten_header)+
			FLCTRL.HDR.root_addr_count*sizeof(size_t)+FLCTRL.HDR.root_addr_extended_size+FLCTRL.HDR.ptr_count*sizeof(size_t));
	printf("--- Fragment array offset: 0x%lx\n",sizeof(size_t)+sizeof(struct flatten_header)+
			FLCTRL.HDR.root_addr_count*sizeof(size_t)+FLCTRL.HDR.root_addr_extended_size+FLCTRL.HDR.ptr_count*sizeof(size_t)+
			FLCTRL.HDR.fptr_count*sizeof(size_t));
	size_t memoff = sizeof(size_t)+sizeof(struct flatten_header)+
			FLCTRL.HDR.root_addr_count*sizeof(size_t)+FLCTRL.HDR.root_addr_extended_size+FLCTRL.HDR.ptr_count*sizeof(size_t)+
			FLCTRL.HDR.fptr_count*sizeof(size_t)+FLCTRL.HDR.mcount*2*sizeof(size_t);
	printf("--- Memory offset: 0x%lx\n",memoff);
	printf("--- Function pointer map offset: 0x%lx\n",sizeof(size_t)+sizeof(struct flatten_header)+
			FLCTRL.HDR.root_addr_count*sizeof(size_t)+FLCTRL.HDR.root_addr_extended_size+FLCTRL.HDR.ptr_count*sizeof(size_t)+
			FLCTRL.HDR.fptr_count*sizeof(size_t)+FLCTRL.HDR.mcount*2*sizeof(size_t)+FLCTRL.HDR.memory_size);
	size_t memsz = FLCTRL.HDR.memory_size+FLCTRL.HDR.ptr_count*sizeof(size_t)+FLCTRL.HDR.fptr_count*sizeof(size_t)+FLCTRL.HDR.mcount*2*sizeof(size_t);
	FLCTRL.mem = malloc(memsz);
	assert(FLCTRL.mem);
	rd = fread(FLCTRL.mem,1,memsz,f);
	if (rd!=memsz) return -1; else readin+=rd;
	if ((FLCTRL.HDR.fptr_count>0)&&(FLCTRL.HDR.fptrmapsz>0)&&(gfa)) {
		unsigned char* fptrmapmem = (unsigned char*)malloc(FLCTRL.HDR.fptrmapsz);
		assert(fptrmapmem);
		rd = fread(fptrmapmem,1,FLCTRL.HDR.fptrmapsz,f);
		if (rd!=FLCTRL.HDR.fptrmapsz) return -1; else readin+=rd;
		size_t fptrnum = *((size_t*)fptrmapmem);
		fptrmapmem+=sizeof(size_t);
		for (size_t kvi=0; kvi<fptrnum; ++kvi) {
			uintptr_t addr = *((uintptr_t*)fptrmapmem);
			//printf("F[%lx]\n",addr);
			fptrmapmem+=sizeof(uintptr_t);
			size_t sz = *((size_t*)fptrmapmem);
			fptrmapmem+=sizeof(size_t);
			fptrmap_insert(addr,(const char*)fptrmapmem,sz);
			fptrmapmem+=sz;
		}
		free(fptrmapmem-FLCTRL.HDR.fptrmapsz);
	}
	if ((FLCTRL.option&option_silent)==0) {
		printf("# Unflattening done. Summary:\n");
		TIME_CHECK_FMT(unfl_b,read_e,"  Image read time: %fs\n");
	}
	TIME_MARK_START(create_b);
	size_t* minfoptr = (size_t*)(((unsigned char*)FLCTRL.mem)+FLCTRL.HDR.ptr_count*sizeof(size_t)+FLCTRL.HDR.fptr_count*sizeof(size_t));
	unsigned char* memptr = ((unsigned char*)FLCTRL.mem)+FLCTRL.HDR.ptr_count*sizeof(size_t)+FLCTRL.HDR.fptr_count*sizeof(size_t)+FLCTRL.HDR.mcount*2*sizeof(size_t);
	for (size_t i=0; i<FLCTRL.HDR.mcount; ++i) {
		size_t index = *minfoptr++;
		size_t size = *minfoptr++;
		//printf("MEM: %08u [%zu]\n",index,size);
		struct interval_tree_node *node = (struct interval_tree_node*)calloc(1,sizeof(struct interval_tree_node));
		node->start = index;
		node->last = index+size-1;
		void* fragment = malloc(size);
		assert(fragment!=0);
		memcpy(fragment,memptr+index,size);
		node->mptr = fragment;
		struct rb_node* rb = interval_tree_insert(node, &FLCTRL.imap_root);
	}
	if ((FLCTRL.option&option_silent)==0) {
		TIME_CHECK_FMT(create_b,create_e,"  Creating memory time: %fs\n");
	}
	TIME_MARK_START(fix_b);
	for (size_t i=0; i<FLCTRL.HDR.root_addr_count; ++i) {
		size_t root_addr_offset = root_addr_array[i];
		root_addr_append(root_addr_offset);
	}
	free(root_addr_array);
	for (size_t i=0; i<FLCTRL.HDR.ptr_count; ++i) {
		void* mem = (unsigned char*)FLCTRL.mem+FLCTRL.HDR.ptr_count*sizeof(size_t)+FLCTRL.HDR.fptr_count*sizeof(size_t)+FLCTRL.HDR.mcount*2*sizeof(size_t);
		size_t fix_loc = *((size_t*)FLCTRL.mem+i);
		struct interval_tree_node *node = interval_tree_iter_first(&FLCTRL.imap_root,fix_loc,fix_loc+8);
		assert(node);
		size_t node_offset = fix_loc-node->start;
		uintptr_t ptr = (uintptr_t)( *((void**)((unsigned char*)mem+fix_loc)) );
		struct interval_tree_node *ptr_node = interval_tree_iter_first(&FLCTRL.imap_root,ptr,ptr+8);
		if (!ptr_node) {
			printf("Couldn't fix memory at @ %zu: [%lx]^[0x%lx]: (%lx)\n",i,fix_loc,memoff+fix_loc,ptr);
			continue;
		}
		size_t ptr_node_offset = ptr-ptr_node->start;
		/* Make the fix */
		*((void**)((unsigned char*)node->mptr+node_offset)) = (unsigned char*)ptr_node->mptr + ptr_node_offset;
	}
	unsigned long fptrstub_count = 0;
	if ((FLCTRL.HDR.fptr_count>0)&&(gfa)) {
		unsigned char* mem = (unsigned char*)FLCTRL.mem+FLCTRL.HDR.ptr_count*sizeof(size_t)+FLCTRL.HDR.fptr_count*sizeof(size_t)+FLCTRL.HDR.mcount*2*sizeof(size_t);
		for (size_t fi=0; fi<FLCTRL.HDR.fptr_count; ++fi) {
			size_t fptri = ((uintptr_t*)((unsigned char*)FLCTRL.mem+FLCTRL.HDR.ptr_count*sizeof(size_t)))[fi];
			struct interval_tree_node *node = interval_tree_iter_first(&FLCTRL.imap_root,fptri,fptri+8);
			assert(node);
			size_t node_offset = fptri-node->start;
			uintptr_t fptrv = *((uintptr_t*)((unsigned char*)node->mptr+node_offset));
			struct fptrmap_node* fnode = fptrmap_search(fptrv);
			if (fnode) {
				uintptr_t nfptr = (*gfa)(fnode->f);
				// Fix function pointer
				if (nfptr) {
					*((void**)((unsigned char*)node->mptr+node_offset)) = (void*)nfptr;
					fptrstub_count++;
				}
			}
			else {
			}
		}
	}
	if ((FLCTRL.option&option_silent)==0) {
		TIME_CHECK_FMT(fix_b,fix_e,"  Fixing memory time: %fs\n");
		TIME_CHECK_FMT(unfl_b,fix_e,"  Total time: %fs\n");
		printf("  Total bytes read: %zu\n",readin);
		printf("  Number of allocated fragments: %zu\n",FLCTRL.HDR.mcount);
		if ((FLCTRL.HDR.fptr_count>0)&&(gfa)) {
			printf("  Number of fixed function pointers: %lu\n",fptrstub_count);
		}
	}

	return 0;
}

int unflatten_read(FILE* f, get_function_address_t gfa) {

	TIME_MARK_START(unfl_b);
	size_t readin = 0;
	size_t rd = fread(&FLCTRL.HDR,sizeof(struct flatten_header),1,f);
	if (rd!=1) return -1; else readin+=sizeof(struct flatten_header);
	if (FLCTRL.HDR.magic!=FLATTEN_MAGIC) {
		fprintf(stderr,"Invalid magic while reading flattened image\n");
		return -1;
	}
	size_t i;
	for (i=0; i<FLCTRL.HDR.root_addr_count; ++i) {
		size_t root_addr_offset;
		size_t rd = fread(&root_addr_offset,sizeof(size_t),1,f);
		if (rd!=1) return -1; else readin+=sizeof(size_t);
		root_addr_append(root_addr_offset);
	}
	size_t memsz = FLCTRL.HDR.memory_size+FLCTRL.HDR.ptr_count*sizeof(size_t)+FLCTRL.HDR.fptr_count*sizeof(size_t)+FLCTRL.HDR.mcount*2*sizeof(size_t);
	FLCTRL.mem = malloc(memsz);
	assert(FLCTRL.mem);
	rd = fread(FLCTRL.mem,1,memsz,f);
	if (rd!=memsz) return -1; else readin+=rd;
	if ((FLCTRL.HDR.fptr_count>0)&&(FLCTRL.HDR.fptrmapsz>0)&&(gfa)) {
		unsigned char* fptrmapmem = (unsigned char*)malloc(FLCTRL.HDR.fptrmapsz);
		assert(fptrmapmem);
		rd = fread(fptrmapmem,1,FLCTRL.HDR.fptrmapsz,f);
		if (rd!=FLCTRL.HDR.fptrmapsz) return -1; else readin+=rd;
		size_t fptrnum = *((size_t*)fptrmapmem);
		fptrmapmem+=sizeof(size_t);
		for (size_t kvi=0; kvi<fptrnum; ++kvi) {
			uintptr_t addr = *((uintptr_t*)fptrmapmem);
			fptrmapmem+=sizeof(uintptr_t);
			size_t sz = *((size_t*)fptrmapmem);
			fptrmapmem+=sizeof(size_t);
			fptrmap_insert(addr,(const char*)fptrmapmem,sz);
			fptrmapmem+=sz;
		}
		free(fptrmapmem-FLCTRL.HDR.fptrmapsz);
	}
	if ((FLCTRL.option&option_silent)==0) {
		printf("# Unflattening done. Summary:\n");
		TIME_CHECK_FMT(unfl_b,read_e,"  Image read time: %fs\n");
	}
	TIME_MARK_START(fix_b);
	fix_unflatten_memory(&FLCTRL.HDR,FLCTRL.mem);
	if ((FLCTRL.HDR.fptr_count>0)&&(gfa)) {
		unsigned char* mem = (unsigned char*)FLCTRL.mem+FLCTRL.HDR.ptr_count*sizeof(size_t)+FLCTRL.HDR.fptr_count*sizeof(size_t)+FLCTRL.HDR.mcount*2*sizeof(size_t);
		for (size_t fi=0; fi<FLCTRL.HDR.fptr_count; ++fi) {
			size_t fptri = ((uintptr_t*)((unsigned char*)FLCTRL.mem+FLCTRL.HDR.ptr_count*sizeof(size_t)))[fi];
			uintptr_t fptrv = *((uintptr_t*)(mem+fptri));
			struct fptrmap_node* fnode = fptrmap_search(fptrv);
			if (fnode) {
				uintptr_t nfptr = (*gfa)(fnode->f);
				// Fix function pointer
				*((void**)(mem+fptri)) = (void*)nfptr;
			}
			else {
			}
		}
	}
	if ((FLCTRL.option&option_silent)==0) {
		TIME_CHECK_FMT(fix_b,fix_e,"  Fixing memory time: %fs\n");
		TIME_CHECK_FMT(unfl_b,fix_e,"  Total time: %fs\n");
		printf("  Total bytes read: %zu\n",readin);
	}
	return 0;
}

void unflatten_fini() {
	FLCTRL.rtail = FLCTRL.rhead;
    while(FLCTRL.rtail) {
    	struct root_addrnode* p = FLCTRL.rtail;
    	FLCTRL.rtail = FLCTRL.rtail->next;
    	free(p);
    }
    free(FLCTRL.mem);
    fptrmap_destroy();
    // TODO: clear interval tree nodes and memory fragments
}

uintptr_t get_fpointer_test_function_address(const char* fsym) {

	struct fptrstub_node* node = fptrstubset_search(fsym);
	if (node) {
		return node->address;
	}

	return 0;
}

void aot_kflat_init(const char* imgpath) {

	FILE* in = fopen(imgpath, "r");
	if (!in) {
		printf("Couldn't open flatten image: %s\n",imgpath);
		exit(2);
	}
	size_t size;
	fread(&size,sizeof(size_t),1,in);
	printf("--- Size of flatten image: %zu\n",size);
	initialize_function_pointer_stubs();
	initialize_fptrstubset();
	unflatten_init();
	assert(unflatten_create(in,get_fpointer_test_function_address) == 0);
	aot_kflat_initialize_global_variables();
	fclose(in);
}

void aot_kflat_fini(void) {
	unflatten_fini();
}
