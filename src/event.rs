//!
//! Utilities for dealing debugger event
//!

use crate::{
    breakpoint::UDbgBreakpoint,
    os::tid_t,
    shell::*,
    symbol::UDbgModule,
    target::{TraceContext, UDbgTarget},
};
use core::pin::Pin;
use core::{fmt, marker::Unpin};
use core::{
    future::Future,
    task::{Context, Poll},
};
use futures::task::{waker_ref, ArcWake};
use spin::mutex::Mutex;
use std::{cell::Cell, rc::Rc};
use std::{sync::Arc, time::Instant};

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum UserReply {
    Run(bool), // handled: bool, for exception
    StepIn,
    StepOut,
    Goto(usize),
    Native(usize),
    Lua,
}

pub type EventPumper = Pin<Box<dyn Future<Output = ()> + 'static>>;

pub struct EventData {
    pub event: Mutex<Option<UEvent>>,
    pub reply: Mutex<UserReply>,
    pub ctx: Cell<Option<*mut dyn TraceContext>>,
}

#[derive(Deref)]
pub struct UEventState(Rc<EventData>);

impl Clone for UEventState {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Default for UEventState {
    fn default() -> Self {
        Self(Rc::new(EventData {
            reply: Mutex::new(UserReply::Run(true)),
            event: Mutex::new(None),
            ctx: Cell::new(None),
        }))
    }
}

impl UEventState {
    pub fn cont(&self) -> AsyncEvent {
        self.event.lock().take();
        AsyncEvent(self.0.clone())
    }

    pub fn context(&self) -> &mut dyn TraceContext {
        unsafe { self.ctx.get().unwrap().as_mut().unwrap() }
    }

    pub fn reply(&self, reply: UserReply) {
        *self.reply.lock() = reply;
    }

    pub async fn loop_util<F: FnMut(&Arc<dyn UDbgTarget>, &UEvent) -> bool>(
        &self,
        mut exit: F,
    ) -> Arc<dyn UDbgTarget> {
        loop {
            let event = self.cont().await;
            let target = self.context().target();
            if exit(&target, &event) {
                return target;
            }
            self.reply(match event {
                UEvent::Exception { .. } => UserReply::Run(false),
                _ => UserReply::Run(true),
            });
        }
    }
}

pub struct AsyncEvent(Rc<EventData>);

impl Future for AsyncEvent {
    type Output = UEvent;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.0.event.lock().clone() {
            Some(e) => Poll::Ready(e),
            None => Poll::Pending,
        }
    }
}

#[derive(Clone, Display)]
pub enum UEvent {
    #[display(fmt = "InitBp")]
    InitBp,
    #[display(fmt = "Step")]
    Step,
    #[display(
        fmt = "Bp {{ address={:x} type={:?} }}",
        "_0.address()",
        "_0.get_type()"
    )]
    Breakpoint(Arc<dyn UDbgBreakpoint>),
    #[display(fmt = "ThreadCreate({_0})")]
    ThreadCreate(tid_t),
    #[display(fmt = "ThreadExit({_0})")]
    ThreadExit(u32),
    #[display(fmt = "ModuleLoad({:x?})", "_0.data()")]
    ModuleLoad(Arc<dyn UDbgModule>),
    #[display(fmt = "ModuleUnload({:x?})", "_0.data()")]
    ModuleUnload(Arc<dyn UDbgModule>),
    #[display(fmt = "ProcessCreate")]
    ProcessCreate,
    #[display(fmt = "ProcessExit({_0})")]
    ProcessExit(u32),
    #[display(fmt = "Exception {{ first: {first}, code: 0x{code:x} }}")]
    Exception { first: bool, code: u32 },
}

impl Unpin for UEvent {}

impl fmt::Debug for UEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// An asynchronous procedure for handling debug event
/// CANNOT mix it with other asynchronous runtime
pub struct DebugTask {
    pub state: UEventState,
    pub ended: bool,
    future: EventPumper,
}

impl DebugTask {
    pub fn new(e: EventPumper, state: UEventState) -> Self {
        Self {
            future: e,
            state,
            ended: false,
        }
    }

    fn step(&mut self) -> Poll<()> {
        let waker = waker_ref(DummyTask::get());
        let context = &mut Context::from_waker(&*waker);
        self.future.as_mut().poll(context)
    }

    pub fn run_step(&mut self, event: UEvent) -> Option<UserReply> {
        self.state.event.lock().replace(event.into());
        match self.step() {
            Poll::Pending => Some(self.state.reply.lock().clone()),
            Poll::Ready(_) => {
                self.ended = true;
                None
            }
        }
    }
}

impl<F: FnOnce(UEventState) -> C, C: Future<Output = ()> + 'static> From<F> for DebugTask {
    fn from(callback: F) -> Self {
        let state = UEventState::default();
        let mut result = Self::new(Box::pin(callback(UEventState::clone(&state))), state);
        result.step();
        result
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

        unsafe { INSTANCE.get_or_insert_with(|| Arc::new(Self)) }
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
            tid: None,
            step_in: false,
            util: Box::new(Self::dummy_util),
        }
    }

    fn dummy_util() -> Result<bool, &'static str> {
        Err("")
    }

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
