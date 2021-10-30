
use super::*;

use std::{sync::Arc, time::Instant};
use std::rc::Rc;
use core::pin::Pin;
use core::marker::Unpin;
use core::{
    future::Future,
    task::{Context, Poll},
};
use llua::*;
use spin::mutex::Mutex;

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
    pub event: Option<UEvent>,
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

    pub fn on(&self, event: UEvent) -> Reply {
        let r = self.0.clone(); {
            let mut c = r.lock();
            c.reply = None;
            c.event = Some(event);
        }
        Reply(r)
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

pub enum UEvent {
    InitBp,
    Step,
    Bp(Arc<dyn UDbgBreakpoint>),
    ThreadCreate,
    ThreadExit(u32),
    ModuleLoad(Arc<dyn UDbgModule>),
    ModuleUnload(Arc<dyn UDbgModule>),
    ProcessCreate,
    ProcessExit(u32),
    Exception {first: bool, code: u32},
}

impl Unpin for UEvent {}

pub trait UtilFunc = FnMut() -> Result<bool, &'static str>;

pub struct UDbgTracer {
    pub tid: Option<tid_t>,
    pub step_in: bool,
    pub begin_time: Instant,
    // if meet the conditions then Ok(true), Err(_) if error
    pub util: Box<dyn UtilFunc>,
}

impl UDbgTracer {
    pub fn new() -> Self {
        Self {
            begin_time: Instant::now(),
            tid: None, step_in: false,
            util: Box::new(Self::dummy_util),
        }
    }

    fn dummy_util() -> Result<bool, &'static str> { Err("") }

    pub fn start(&mut self, tid: tid_t, step_in: bool, util: impl UtilFunc + 'static) {
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

    pub fn start_lua_trace(&mut self, tid: tid_t, s: &State, step_in: bool) {
        s.push_value(2);
        let lref = s.reference(LUA_REGISTRYINDEX);
        let s = unsafe { s.copy_state() };
        self.start(tid, step_in, move || s.balance_with(|s| {
            s.raw_geti(LUA_REGISTRYINDEX, lref.0 as lua_Integer);
            let result = if s.pcall(0, 1, 0).is_err() {
                s.unreference(LUA_REGISTRYINDEX, lref);
                Err(s.to_str(-1).unwrap_or(""))
            } else {
                let b = s.to_bool(-1);
                if b { s.unreference(LUA_REGISTRYINDEX, lref); }
                Ok(b)
            };
            result
        }));
    }
}