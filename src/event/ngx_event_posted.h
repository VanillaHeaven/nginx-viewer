#ifndef _NGX_EVENT_POSTED_H_INCLUDED_
#define _NGX_EVENT_POSTED_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define ngx_post_event(ev)                                                    \
                ev->next = (ngx_event_t *) ngx_posted_events;                 \
                ngx_posted_events = ev;                                       \
                ev->posted = 1;


void ngx_event_process_posted(ngx_cycle_t *cycle);
#if (NGX_THREADS)
void ngx_event_thread_handler(ngx_event_t *ev);
#endif


extern ngx_thread_volatile ngx_event_t  *ngx_posted_events;
#if (NGX_THREADS)
extern ngx_mutex_t                      *ngx_posted_events_mutex;
#endif


#endif /* _NGX_EVENT_POSTED_H_INCLUDED_ */