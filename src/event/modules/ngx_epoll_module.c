
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (TEST_BUILD_EPOLL)

/* epoll declarations */

#define EPOLLIN        0x001
#define EPOLLPRI       0x002
#define EPOLLOUT       0x004
#define EPOLLRDNORM    0x040
#define EPOLLRDBAND    0x080
#define EPOLLWRNORM    0x100
#define EPOLLWRBAND    0x200
#define EPOLLMSG       0x400
#define EPOLLERR       0x008
#define EPOLLHUP       0x010

#define EPOLLET        0x80000000
#define EPOLLONESHOT   0x40000000

#define EPOLL_CTL_ADD  1
#define EPOLL_CTL_DEL  2
#define EPOLL_CTL_MOD  3

typedef union epoll_data {
    void         *ptr;
    int           fd;
    uint32_t      u32;
    uint64_t      u64;
} epoll_data_t;

struct epoll_event {
    uint32_t      events;
    epoll_data_t  data;
};

int epoll_create(int size);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout);

int epoll_create(int size)
{
    return -1;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return -1;
}

int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout)
{
    return -1;
}

#endif


typedef struct {
    u_int  events;
} ngx_epoll_conf_t;


static int ngx_epoll_init(ngx_cycle_t *cycle);
static void ngx_epoll_done(ngx_cycle_t *cycle);
static int ngx_epoll_add_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_epoll_del_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_epoll_add_connection(ngx_connection_t *c);
static int ngx_epoll_del_connection(ngx_connection_t *c, u_int flags);
static int ngx_epoll_process_events(ngx_cycle_t *cycle);

static void *ngx_epoll_create_conf(ngx_cycle_t *cycle);
static char *ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf);

static int                  ep = -1;
static struct epoll_event  *event_list;
static u_int                nevents;


static ngx_str_t      epoll_name = ngx_string("epoll");

static ngx_command_t  ngx_epoll_commands[] = {

    {ngx_string("epoll_events"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_epoll_conf_t, events),
     NULL},

    ngx_null_command
};


ngx_event_module_t  ngx_epoll_module_ctx = {
    &epoll_name,
    ngx_epoll_create_conf,               /* create configuration */
    ngx_epoll_init_conf,                 /* init configuration */

    {
        ngx_epoll_add_event,             /* add an event */
        ngx_epoll_del_event,             /* delete an event */
        ngx_epoll_add_event,             /* enable an event */
        ngx_epoll_del_event,             /* disable an event */
        ngx_epoll_add_connection,        /* add an connection */
        ngx_epoll_del_connection,        /* delete an connection */
        NULL,                            /* process the changes */
        ngx_epoll_process_events,        /* process the events */
        ngx_epoll_init,                  /* init the events */
        ngx_epoll_done,                  /* done the events */
    }
};

ngx_module_t  ngx_epoll_module = {
    NGX_MODULE,
    &ngx_epoll_module_ctx,               /* module context */
    ngx_epoll_commands,                  /* module directives */
    NGX_EVENT_MODULE,                    /* module type */
    NULL,                                /* init module */
    NULL                                 /* init process */
};


/* 创建epoll对象，赋值ngx_event_actions */
static int ngx_epoll_init(ngx_cycle_t *cycle)
{
    size_t             n;
    ngx_event_conf_t  *ecf;
    ngx_epoll_conf_t  *epcf;

    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);

    epcf = ngx_event_get_conf(cycle->conf_ctx, ngx_epoll_module);

    if (ep == -1) {
        /* 这里数量为什么是连接的一半？
         * 在最初的epoll_create（）实现中，size参数将调用者希望添加到的文件描述符的数量告知内核。epoll实例。
         * 内核使用该信息作为内部数据结构初始分配空间的提示，事件。 
         * （如果有必要，如果调用方的使用超出了大小提示，内核将分配更多空间。）
         * 如今，此提示不再必需（内核无需提示即可动态调整所需数据结构的大小），但是大小必须仍大于零，
         * 以便当新的epoll应用程序在较旧的内核上运行时，请确保向后兼容。
         */
        ep = epoll_create(ecf->connections / 2);

        if (ep == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "epoll_create() failed");
            return NGX_ERROR;
        }
    }

    if (nevents < epcf->events) {
        // 这个数组决定了一次收集事件的个数
        if (event_list) {
            ngx_free(event_list);
        }

        event_list = ngx_alloc(sizeof(struct epoll_event) * epcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return NGX_ERROR;
        }
    }

    nevents = epcf->events;

    /*??? 似乎设置了io的一些回调
     * 设置了tcp读写的一些回调
     */
    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_epoll_module_ctx.actions;

    /* 支持边沿触发，这里宏的名字为什么这么叫？ */
#if (HAVE_CLEAR_EVENT)
    ngx_event_flags = NGX_USE_CLEAR_EVENT
#else
    /* 水平触发 */
    ngx_event_flags = NGX_USE_LEVEL_EVENT
#endif
                      |NGX_HAVE_GREEDY_EVENT
                      |NGX_USE_EPOLL_EVENT;

    return NGX_OK;
}


/* 关闭ep的描述符，释放对应结构内存 */
static void ngx_epoll_done(ngx_cycle_t *cycle)
{
    if (close(ep) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "epoll close() failed");
    }

    ep = -1;

    ngx_free(event_list);

    event_list = NULL;
    nevents = 0;
}


static int ngx_epoll_add_event(ngx_event_t *ev, int event, u_int flags)
{
    int                  op, prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;

    c = ev->data;

    /*
     * 不是读就是写事件？
     * 看这个逻辑一定读写一定是交错的？
     */
    if (event == NGX_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;
#if (NGX_READ_EVENT != EPOLLIN)
        event = EPOLLIN;
#endif

    } else {
        e = c->read;
        prev = EPOLLIN;
#if (NGX_WRITE_EVENT != EPOLLOUT)
        event = EPOLLOUT;
#endif
    }

    if (e->active) {
        /* 如果上一个事件是活跃的
         * 说明请求在处理中，
         * 那么连接是既可读，也可写的
         */
        op = EPOLL_CTL_MOD;
        event |= prev;

    } else {
        /*
         * 如果连接是刚被激活，
         * 那么就添加ADD它
         */
        op = EPOLL_CTL_ADD;
    }

    ee.events = event | flags;
    /* 事件处理的对象指针 */
    ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll add event: fd:%d op:%d ev:%08X",
                   c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    /* 激活事件 */
    ev->active = 1;
#if 0
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;
#endif

    return NGX_OK;
}


static int ngx_epoll_del_event(ngx_event_t *ev, int event, u_int flags)
{
    int                  op, prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;

    /*
     * when the file descriptor is closed the epoll automatically deletes
     * it from its queue so we do not need to delete explicity the event
     * before the closing the file descriptor
     */

    if (flags & NGX_CLOSE_EVENT) {
        ev->active = 0;
        return NGX_OK;
    }

    c = ev->data;

    if (event == NGX_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;

    } else {
        e = c->read;
        prev = EPOLLIN;
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        ee.events = prev | flags;
        ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    } else {
        /* 只有连接不活跃了才真的删除事件 */
        op = EPOLL_CTL_DEL;
        ee.events = 0;
        ee.data.ptr = NULL;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll del event: fd:%d op:%d ev:%08X",
                   c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    ev->active = 0;

    return NGX_OK;
}


static int ngx_epoll_add_connection(ngx_connection_t *c)
{
    struct epoll_event  ee;

    ee.events = EPOLLIN|EPOLLOUT|EPOLLET;
    ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll add connection: fd:%d ev:%08X", c->fd, ee.events);

    if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, %d) failed", c->fd);
        return NGX_ERROR;
    }

    c->read->active = 1;
    c->write->active = 1;

    return NGX_OK;
}


static int ngx_epoll_del_connection(ngx_connection_t *c, u_int flags)
{
    int                  op;
    struct epoll_event   ee;

    /*
     * when the file descriptor is closed the epoll automatically deletes
     * it from its queue so we do not need to delete explicity the event
     * before the closing the file descriptor
     */

    if (flags & NGX_CLOSE_EVENT) {
        c->read->active = 0;
        c->write->active = 0;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll del connection: fd:%d", c->fd);

    op = EPOLL_CTL_DEL;
    ee.events = 0;
    ee.data.ptr = NULL;

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    c->read->active = 0;
    c->write->active = 0;

    return NGX_OK;
}


/*
 让我们一起看看事件驱动的核心逻辑函数 
 先总体浏览一遍，
 疑惑的地方先打个标记
*/
int ngx_epoll_process_events(ngx_cycle_t *cycle)
{
    int                events;
    size_t             n;
    ngx_int_t          instance, i;
    ngx_uint_t         lock, accept_lock, expire;
    ngx_err_t          err;
    ngx_log_t         *log;
    ngx_msec_t         timer;
    ngx_event_t       *rev, *wev;
    struct timeval     tv;
    ngx_connection_t  *c;
    ngx_epoch_msec_t   delta;

    for ( ;; ) { 
        /*
         * timer是定时器事件中，最旧的一个事件的超时时间
         * 最旧的事件超时时间大于0，说明所有的定时器事件都还没到处理时间，
         * 所以把 timer 返回出来，作为epoll_wait的超时时间
         * 最旧的事件超时时间小于0时，表示已经有事件超时了，所以需要立即处理这些超时事件，在下面ngx_event_expire_timers处理
         * 为了跟-1做区分，timer会返回值0。
         * timer为-1表示，定时器中没有事件，那么就不需要为epoll设置超时时间了，无限等就行。
         */
        timer = ngx_event_find_timer();

#if (NGX_THREADS)

        if (timer == NGX_TIMER_ERROR) {
            return NGX_ERROR;
        }

        if (timer == NGX_TIMER_INFINITE || timer > 500) {
            timer = 500;
            break;
        }

#endif

        if (timer != 0) {
            break;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "epoll expired timer");

        /**
         * @brief 
         * 处理超时事件
         */
        ngx_event_expire_timers((ngx_msec_t)
                                    (ngx_elapsed_msec - ngx_old_elapsed_msec));

        if (ngx_posted_events && ngx_threaded) {
            ngx_wakeup_worker_thread(cycle);
        }
    }

    /* NGX_TIMER_INFINITE == INFTIM 
     * timer > 0 or timer == -1
     */

    if (timer == NGX_TIMER_INFINITE) {
        expire = 0;

    } else {
        /**
         * @brief 
         * 如果是timer>0，那就有可能会超时，
         * 所以标记下，最后再处理一波
         */
        expire = 1;
    }

    ngx_old_elapsed_msec = ngx_elapsed_msec;
    accept_lock = 0;

    /* 这里一段获取锁的逻辑
     * 任何锁的操作，都是对共享资源的处理
     *
     * 如果ngx_accept_mutex指针的地址不为NULL，
     * 那么就进入争抢锁的逻辑
     */
    if (ngx_accept_mutex) {
        /**
         * @brief 
         * ngx_accept_disabled是担心一个进程处理的连接过多，
         * 所以如果ngx_accept_disabled大于0时，
         * 就不允许它再去抢accept锁
         */
        if (ngx_accept_disabled > 0) {
            ngx_accept_disabled--;

        } else {
            /* 尝试对什么资源加锁，争抢资源，争抢对请求的处理权？
             * ngx_trylock_accept_mutex 应该是用于标识，进程是否已经抢到了接收连接事件的处理权
             */
            if (ngx_trylock_accept_mutex(cycle) == NGX_ERROR) {
                return NGX_ERROR;
            }

            /* 拿到资源了 */
            if (ngx_accept_mutex_held) {
                accept_lock = 1;

            /**
             * @brief 
             * epoll_wait timer的时间不会超过ngx_accept_mutex_delay的时间
             * ngx_accept_mutex_delay是一个进程获取到accept锁之后，
             * 再次获取到accept最小间隔时间
             */
            } else if (timer == NGX_TIMER_INFINITE
                       || timer > ngx_accept_mutex_delay)
            {
                timer = ngx_accept_mutex_delay;
                expire = 0;
            }
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "epoll timer: %d", timer);

    events = epoll_wait(ep, event_list, nevents, timer);

    if (events == -1) {
        err = ngx_errno;
    } else {
        err = 0;
    }

    ngx_gettimeofday(&tv);
    ngx_time_update(tv.tv_sec);

    delta = ngx_elapsed_msec;
    ngx_elapsed_msec = (ngx_epoch_msec_t) tv.tv_sec * 1000
                                          + tv.tv_usec / 1000 - ngx_start_msec;

    if (timer != NGX_TIMER_INFINITE) {
        delta = ngx_elapsed_msec - delta;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "epoll timer: %d, delta: %d", timer, (int) delta);
    } else {
        /* timer为-1时，返回的事件个数一定不为0的 */
        if (events == 0) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "epoll_wait() returned no events without timeout");
            ngx_accept_mutex_unlock();
            return NGX_ERROR;
        }
    }

    if (err) {
        ngx_log_error((err == NGX_EINTR) ? NGX_LOG_INFO : NGX_LOG_ALERT,
                      cycle->log, err, "epoll_wait() failed");
        ngx_accept_mutex_unlock();
        return NGX_ERROR;
    }

    if (events > 0) {
        /* #define ngx_mutex_lock NGX_OK 
         * NGX_OK == NGX_ERROR? 什么鬼
         * 如果epoll事件个数大于0，就要尝试获取post延后事件锁
         */
        if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
            ngx_accept_mutex_unlock();
            return NGX_ERROR;
        } 

        lock = 1;

    } else {
        lock =0;
    }

    log = cycle->log;

    for (i = 0; i < events; i++) {
        c = event_list[i].data.ptr;

        /**
         * @brief 
         * 连接被释放后，又被取出来当其他请求的连接
         * instance用来标记是不是不同的请求获取相同的连接
         */
        instance = (uintptr_t) c & 1;
        c = (ngx_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);

        rev = c->read;

        /* nginx巧妙的用链接类型的最后一个bit
         * 做了一些事情
         */
        if (c->fd == -1 || rev->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll: stale event " PTR_FMT, c);
            continue;
        }

#if (NGX_DEBUG0)
        log = c->log ? c->log : cycle->log;
#endif

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, log, 0,
                       "epoll: fd:%d ev:%04X d:" PTR_FMT,
                       c->fd, event_list[i].events, event_list[i].data);

        if (event_list[i].events & (EPOLLERR|EPOLLHUP)) {
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
                           "epoll_wait() error on fd:%d ev:%04X",
                           c->fd, event_list[i].events);
        }

        if (event_list[i].events & ~(EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP)) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "strange epoll_wait() events fd:%d ev:%04X",
                          c->fd, event_list[i].events);
        }

        wev = c->write;

        if ((event_list[i].events & (EPOLLOUT|EPOLLERR|EPOLLHUP))
            && wev->active)
        {
            if (ngx_threaded) {
                wev->posted_ready = 1;
                ngx_post_event(wev);

            } else {
                wev->ready = 1;

                if (!ngx_accept_mutex_held) {
                    wev->event_handler(wev);

                } else {
                    /* 如果抢到accept锁了，就延后处理写事件 */
                    ngx_post_event(wev);
                }
            }
        }

        /*
         * EPOLLIN must be handled after EPOLLOUT because we use
         * the optimization to avoid the unnecessary mutex locking/unlocking
         * if the accept event is the last one.
         */

        if ((event_list[i].events & (EPOLLIN|EPOLLERR|EPOLLHUP))
            && rev->active)
        {
            if (ngx_threaded && !rev->accept) {
                rev->posted_ready = 1;

                ngx_post_event(rev);

                continue;
            }

            rev->ready = 1;

            /* 如果并没有获取到accept锁，那么理论上此工作进程处理的都不是accept事件
             * 立即执行即可
             */
            if (!ngx_threaded && !ngx_accept_mutex_held) {
                rev->event_handler(rev);

            /* 否则，本进程就有可能处理accept事件
             * 如果不是accept事件，就放到延迟事件队列中
             */
            } else if (!rev->accept) {
                ngx_post_event(rev);

            /* 处理accept事件 
             * ngx_accept_disabled 大于0时，本进程不能处理accept事件
             */
            } else if (ngx_accept_disabled <= 0) {

                ngx_mutex_unlock(ngx_posted_events_mutex);

                rev->event_handler(rev);

                /* 处理完一个accept事件后，ngx_accept_disabled会在ngx_event_accept函数被更新
                 * 此时有可能大于0，后续的accept事件就不能处理了？
                 */
                if (ngx_accept_disabled > 0) {
                    ngx_accept_mutex_unlock();
                    accept_lock = 0;
                }

                if (i + 1 == events) {
                    lock = 0;
                    break;
                }

                if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
                    if (accept_lock) {
                        ngx_accept_mutex_unlock();
                    }
                    return NGX_ERROR;
                }
            }
        }
    }

    if (accept_lock) {
        ngx_accept_mutex_unlock();
    }

    if (lock) {
        ngx_mutex_unlock(ngx_posted_events_mutex);
    }

    if (expire && delta) {
        ngx_event_expire_timers((ngx_msec_t) delta);
    }

    if (ngx_posted_events) {
        if (ngx_threaded) {
            ngx_wakeup_worker_thread(cycle);

        } else {
            ngx_event_process_posted(cycle);
        }
    }

    return NGX_OK;
}

/* epoll模块的配置就只有一个，设置wait收集事件个数的上限 */
static void *ngx_epoll_create_conf(ngx_cycle_t *cycle)
{
    ngx_epoll_conf_t  *epcf;

    ngx_test_null(epcf, ngx_palloc(cycle->pool, sizeof(ngx_epoll_conf_t)),
                  NGX_CONF_ERROR);

    epcf->events = NGX_CONF_UNSET;

    return epcf;
}


static char *ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_epoll_conf_t *epcf = conf;

    /* 默认初始512个事件 */
    ngx_conf_init_unsigned_value(epcf->events, 512);

    return NGX_CONF_OK;
}
