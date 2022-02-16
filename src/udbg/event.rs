
use super::*;
use crate::sym::UDbgModule;

use std::{sync::Arc, time::Instant};
use std::rc::Rc;
use core::pin::Pin;
use core::marker::Unpin;
use core::{
    future::Future,
    task::{Context, Poll},
};
use spin::mutex::Mutex;
use futures::task::{waker_ref, ArcWake};

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum UserReply {
    Run(bool),      // handled: bool, for exception
    StepIn,
    StepOut,
    Goto(usize),
    Native(usize),
    Lua,
}

pub type EventPumper = Pin<Box<dyn Future<Output=()> + 'static>>;

pub struct EventState {
    pub reply: Option<UserReply>,
    pub event: Option<Option<UEvent>>,
}

#[derive(Deref, Clone)]
pub struct UEventState(Rc<Mutex<EventState>>);

impl UEventState {
    pub fn new() -> Self {
        Self(Rc::new(Mutex::new(EventState {
            reply: None,
            event: None,
        })))
    }

    pub fn cont(&self, reply: UserReply) -> AsyncEvent {
        let r = self.0.clone(); {
            let mut c = r.lock();
            c.reply = Some(reply);
            c.event = None;
        }
        AsyncEvent(r)
    }
}

pub struct AsyncEvent(Rc<Mutex<EventState>>);

impl Future for AsyncEvent {
    type Output = Option<UEvent>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.0.lock().event.take() {
            Some(r) => Poll::Ready(r),
            None => Poll::Pending,
        }
    }
}

pub struct Reply(Rc<Mutex<EventState>>);

impl Future for Reply {
    type Output = UserReply;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.0.lock().reply.take() {
            Some(r) => Poll::Ready(r),
            None => Poll::Pending,
        }
    }
}

#[derive(Display)]
pub enum UEvent {
    #[display(fmt="InitBp")]
    InitBp,
    #[display(fmt="Step")]
    Step,
    #[display(fmt="Bp(address={:x} type={:?})", "_0.address()", "_0.get_type()")]
    Breakpoint(Arc<dyn UDbgBreakpoint>),
    #[display(fmt="ThreadCreate({_0})")]
    ThreadCreate(tid_t),
    #[display(fmt="ThreadExit({_0})")]
    ThreadExit(u32),
    #[display(fmt="ModuleLoad({:x?})", "_0.data()")]
    ModuleLoad(Arc<dyn UDbgModule>),
    #[display(fmt="ModuleUnload({:x?})", "_0.data()")]
    ModuleUnload(Arc<dyn UDbgModule>),
    #[display(fmt="ProcessCreate")]
    ProcessCreate,
    #[display(fmt="ProcessExit({_0})")]
    ProcessExit(u32),
    #[display(fmt="Exception {{ first: {first}, code: 0x{code:x} }}")]
    Exception {first: bool, code: u32},
}

impl Unpin for UEvent {}

pub struct ReplyFetcher {
    future: EventPumper,
    state: UEventState,
}

impl ReplyFetcher {
    pub fn new(e: EventPumper, state: UEventState) -> Self {
        Self { future: e, state }
    }

    pub fn fetch(&mut self, event: impl Into<Option<UEvent>>) -> Option<UserReply> {
        self.state.lock().event = Some(event.into());
        let waker = waker_ref(DummyTask::get());
        let context = &mut Context::from_waker(&*waker);
        match self.future.as_mut().poll(context) {
            Poll::Pending => self.state.lock().reply.take(),
            Poll::Ready(_) => None,
        }
    }
}

struct DummyTask;

impl ArcWake for DummyTask {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        panic!("DummyTask should not be waked");
    }
}

impl DummyTask {
    fn get() -> &'static Arc<DummyTask> {
        static mut INSTANCE: Option<Arc<DummyTask>> = None;

        unsafe {
            INSTANCE.get_or_insert_with(|| Arc::new(Self))
        }
    }
}

pub trait UtilFunc = FnMut() -> Result<bool, &'static str>;

pub struct UDbgTracer<'a> {
    pub tid: Option<tid_t>,
    pub step_in: bool,
    pub begin_time: Instant,
    // if meet the conditions then Ok(true), Err(_) if error
    pub util: Box<dyn UtilFunc + 'a>,
}

impl<'a> UDbgTracer<'a> {
    pub fn new() -> Self {
        Self {
            begin_time: Instant::now(),
            tid: None, step_in: false,
            util: Box::new(Self::dummy_util),
        }
    }

    fn dummy_util() -> Result<bool, &'static str> { Err("") }

    pub fn start(&mut self, tid: tid_t, step_in: bool, util: impl UtilFunc + 'a) {
        self.tid = Some(tid);
        self.step_in = step_in;
        self.util = Box::new(util);
        self.begin_time = Instant::now();
    }

    pub fn end(&mut self) {
        self.tid = None;
        self.util = Box::new(Self::dummy_util);
        let dur = self.begin_time.elapsed().as_millis();
        udbg_ui().info(format!("[trace end] elapsed: {}ms", dur));
    }
}