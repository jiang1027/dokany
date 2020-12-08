#ifndef LIST_INC
#define LIST_INC

struct list_head
{
	struct list_head* next;
	struct list_head* prev;
};

#define INIT_LIST_HEAD(list) \
	do { (list)->next = (list); (list)->prev = (list); } while (0)

#define offset_of(type, member) ((size_t) & (( (type* ) 0 )->member))

#define container_of(ptr, type, member) \
	( (type *) ( (unsigned char*)(ptr) - offset_of(type, member) ) )

#define list_entry(ptr, type, member) container_of(ptr, type, member)


void list_add(struct list_head* entry, struct list_head* head);
void list_add_tail(struct list_head* entry, struct list_head* head);

void list_del(struct list_head* entry);
void list_del_init(struct list_head* entry);

int list_is_empty(const struct list_head* head);

// more readable function name
void list_push_front(struct list_head* head, struct list_head* entry);
void list_push_back(struct list_head* head, struct list_head* entry);

struct list_head* list_pop_front(struct list_head* head);
struct list_head* list_pop_back(struct list_head* head);


#endif // LIST_INC
// end of file
