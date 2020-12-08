#include <stdio.h>
#include "list.h"

void list_add(struct list_head* entry, struct list_head* head)
{
	entry->next = head->next;
	head->next = entry;
	entry->prev = head;
	entry->next->prev = entry;
}


void list_add_tail(struct list_head* entry, struct list_head* head)
{
	head->prev->next = entry;
	entry->next = head;
	entry->prev = head->prev;
	head->prev = entry;
}


void list_del(struct list_head* entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
}


void list_del_init(struct list_head* entry)
{
	list_del(entry);
	INIT_LIST_HEAD(entry);
}


int list_is_empty(const struct list_head* head)
{
	return head->next == head ? 1 : 0;
}


void list_push_front(struct list_head* head, struct list_head* entry)
{
	list_add(entry, head);
}

void list_push_back(struct list_head* head, struct list_head* entry)
{
	list_add(entry, head->prev);
}


struct list_head* list_pop_front(struct list_head* head)
{
	struct list_head* entry;
	if (list_is_empty(head)) return NULL;
	entry = head->next;
	list_del_init(entry);
	return entry;
}

struct list_head* list_pop_back(struct list_head* head)
{
	struct list_head* entry;
	if (list_is_empty(head)) return NULL;
	entry = head->prev;
	list_del_init(entry);
	return entry;
}
