use std::collections::HashMap;
use actix::Message;
use std::hash::Hash;

pub mod trace_analyzer;
pub mod pyroscope_exporter;

pub type FoldedStackTraces = HashMap<StackTrace, usize>;

#[derive(Eq)]
pub struct StackTrace {
    pub frames: Vec<&'static str>
}

// Compare frames' strings by reference as equal symbols would share a reference to the same
// underlying static string
impl PartialEq for StackTrace {
    fn eq(&self, other: &Self) -> bool {
        self.frames.len() == other.frames.len() &&
        self.frames.iter().zip(other.frames.iter()).all(|(&a, &b)| std::ptr::eq(a, b))
    }
}

// Also compute the hash against the pointer address of each stack frame
impl Hash for StackTrace {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_usize(self.frames.len());
        for &frame in &self.frames {
            (frame as *const str).hash(state);
        }
    }
}

#[derive(Message)]
#[rtype("()")]
pub struct FoldedStackTraceBatch {
    pub traces: FoldedStackTraces
}

impl FoldedStackTraceBatch {
    pub fn join_trace(&mut self, trace: StackTrace) -> Option<StackTrace> {
        match self.traces.get_mut(&trace) {
            Some(instances) => {
                *instances += 1;
                Some(trace)
            },
            None => {
                self.traces.insert(trace, 1);
                None
            }
        }
    }
}
