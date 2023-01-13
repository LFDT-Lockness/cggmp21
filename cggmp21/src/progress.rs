//! Traces progress of protocol execution

use std::fmt;
use std::time::{Duration, Instant};

use thiserror::Error;

pub trait Tracer: Send + Sync {
    fn trace_event(&mut self, event: Event);

    fn protocol_begins(&mut self) {
        self.trace_event(Event::ProtocolBegins)
    }
    fn round_begins(&mut self) {
        self.trace_event(Event::RoundBegins { name: None })
    }
    fn named_round_begins(&mut self, round_name: &'static str) {
        self.trace_event(Event::RoundBegins {
            name: Some(round_name),
        })
    }
    fn stage(&mut self, stage: &'static str) {
        self.trace_event(Event::Stage { name: stage })
    }
    fn receive_msgs(&mut self) {
        self.trace_event(Event::ReceiveMsgs)
    }
    fn msgs_received(&mut self) {
        self.trace_event(Event::MsgsReceived)
    }
    fn send_msg(&mut self) {
        self.trace_event(Event::SendMsg)
    }
    fn msg_sent(&mut self) {
        self.trace_event(Event::MsgSent)
    }
    fn protocol_ends(&mut self) {
        self.trace_event(Event::ProtocolEnds)
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Event {
    ProtocolBegins,

    RoundBegins { name: Option<&'static str> },
    Stage { name: &'static str },

    ReceiveMsgs,
    MsgsReceived,

    SendMsg,
    MsgSent,

    ProtocolEnds,
}

impl Tracer for &mut dyn Tracer {
    fn trace_event(&mut self, event: Event) {
        (*self).trace_event(event)
    }
}

impl<T: Tracer> Tracer for &mut T {
    fn trace_event(&mut self, event: Event) {
        <T as Tracer>::trace_event(self, event)
    }
}

impl<T: Tracer> Tracer for Option<T> {
    fn trace_event(&mut self, event: Event) {
        match self {
            Some(tracer) => tracer.trace_event(event),
            None => {
                // no-op
            }
        }
    }
}

pub struct PerfProfiler {
    last_timestamp: Option<Instant>,
    ongoing_stage: Option<usize>,
    protocol_began: Option<Instant>,
    report: PerfReport,
    error: Option<ProfileError>,
}

#[derive(Debug, Clone)]
pub struct PerfReport {
    pub setup: Duration,
    pub setup_stages: Vec<StageDuration>,
    pub rounds: Vec<RoundDuration>,
    display_io: bool,
}

#[derive(Debug, Clone)]
pub struct RoundDuration {
    pub round_name: Option<&'static str>,
    pub stages: Vec<StageDuration>,
    pub computation: Duration,
    pub sending: Duration,
    pub receiving: Duration,
}

#[derive(Debug, Clone)]
pub struct StageDuration {
    pub name: &'static str,
    pub duration: Duration,
}

#[derive(Debug, Error, Clone)]
#[error("profiler failed to trace protocol: it behaved unexpectedly")]
pub struct ProfileError(
    #[source]
    #[from]
    ErrorReason,
);

#[derive(Debug, Error, Clone)]
pub enum ErrorReason {
    #[error("protocol has never began")]
    ProtocolNeverBegan,
    #[error("tracing stage or sending/receiving message but round never began")]
    RoundNeverBegan,
    #[error("bug: unreachable condition happened")]
    Unreachable,
    #[error("stage is ongoing, but it can't be finished with that event: {event:?}")]
    CantFinishStage { event: Event },
}

impl Tracer for PerfProfiler {
    fn trace_event(&mut self, event: Event) {
        if self.error.is_none() {
            if let Err(err) = self.try_trace_event(event) {
                self.error = Some(err)
            }
        }
    }
}

impl PerfProfiler {
    pub fn new() -> Self {
        Self {
            last_timestamp: None,
            ongoing_stage: None,
            protocol_began: None,
            report: PerfReport {
                setup: Duration::ZERO,
                setup_stages: vec![],
                rounds: vec![],
                display_io: true,
            },
            error: None,
        }
    }

    pub fn get_report(&self) -> Result<PerfReport, ProfileError> {
        if let Some(err) = self.error.clone() {
            Err(err)
        } else {
            Ok(self.report.clone())
        }
    }

    fn try_trace_event(&mut self, event: Event) -> Result<(), ProfileError> {
        let now = Instant::now();

        if Self::event_can_finish_ongoing_stage(&event) {
            if let Some(stage_i) = self.ongoing_stage.take() {
                let last_timestamp = self.last_timestamp()?;

                if !self.report.rounds.is_empty() {
                    let last_round = self.last_round_mut()?;
                    last_round.stages[stage_i].duration += now - last_timestamp;
                } else {
                    self.report.setup_stages[stage_i].duration += now - last_timestamp;
                }
            }
        } else if self.ongoing_stage.is_some() {
            return Err(ErrorReason::CantFinishStage { event }.into());
        }
        match event {
            Event::ProtocolBegins => {
                self.protocol_began = Some(now);
            }
            Event::RoundBegins { name } => {
                let last_timestamp = self.last_timestamp()?;
                match self.report.rounds.last_mut() {
                    None => self.report.setup += now - last_timestamp,
                    Some(last_round) => last_round.computation += now - last_timestamp,
                }
                self.report.rounds.push(RoundDuration {
                    round_name: name,
                    stages: vec![],
                    computation: Duration::ZERO,
                    sending: Duration::ZERO,
                    receiving: Duration::ZERO,
                })
            }
            Event::Stage { name } => {
                let last_timestamp = self.last_timestamp()?;

                let stages = if !self.report.rounds.is_empty() {
                    let last_round = self.last_round_mut()?;
                    last_round.computation += now - last_timestamp;

                    &mut last_round.stages
                } else {
                    self.report.setup += now - last_timestamp;
                    &mut self.report.setup_stages
                };

                let stage_i = stages.iter().position(|s| s.name == name);
                let stage_i = match stage_i {
                    Some(i) => i,
                    None => {
                        stages.push(StageDuration {
                            name,
                            duration: Duration::ZERO,
                        });
                        stages.len() - 1
                    }
                };
                self.ongoing_stage = Some(stage_i);
            }
            Event::ReceiveMsgs => {
                let last_timestamp = self.last_timestamp()?;
                let last_round = self.last_round_mut()?;
                last_round.computation += now - last_timestamp;
            }
            Event::MsgsReceived => {
                let last_timestamp = self.last_timestamp()?;
                let last_round = self.last_round_mut()?;
                last_round.receiving += now - last_timestamp;
            }
            Event::SendMsg => {
                let last_timestamp = self.last_timestamp()?;
                let last_round = self.last_round_mut()?;
                last_round.computation += now - last_timestamp;
            }
            Event::MsgSent => {
                let last_timestamp = self.last_timestamp()?;
                let last_round = self.last_round_mut()?;
                last_round.sending += now - last_timestamp;
            }
            Event::ProtocolEnds => {
                let last_timestamp = self.last_timestamp()?;
                let last_round = self.last_round_mut()?;
                last_round.computation += now - last_timestamp;
            }
        }

        self.last_timestamp = Some(now);
        Ok(())
    }

    fn last_timestamp(&self) -> Result<Instant, ProfileError> {
        let last_timestamp = self.last_timestamp.ok_or(ErrorReason::ProtocolNeverBegan)?;
        Ok(last_timestamp)
    }
    fn last_round_mut(&mut self) -> Result<&mut RoundDuration, ProfileError> {
        let last_round = self
            .report
            .rounds
            .last_mut()
            .ok_or(ErrorReason::RoundNeverBegan)?;
        Ok(last_round)
    }
    fn event_can_finish_ongoing_stage(event: &Event) -> bool {
        matches!(
            event,
            Event::RoundBegins { .. }
                | Event::Stage { .. }
                | Event::ReceiveMsgs
                | Event::SendMsg
                | Event::ProtocolEnds
        )
    }
}

impl Default for PerfProfiler {
    fn default() -> Self {
        Self::new()
    }
}

impl PerfReport {
    pub fn display_io(mut self, display: bool) -> Self {
        self.display_io = display;
        self
    }
}

impl fmt::Display for PerfReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total_computation =
            self.setup + self.rounds.iter().map(|r| r.computation).sum::<Duration>();
        let total_send = self.rounds.iter().map(|r| r.sending).sum::<Duration>();
        let total_recv = self.rounds.iter().map(|r| r.receiving).sum::<Duration>();
        let total_io = total_send + total_recv;
        let total = total_computation + total_io;

        if self.display_io {
            writeln!(f, "Protocol Performance:")?;
            writeln!(f, "  - Protocol took {total:.2?} to complete")?;
            writeln!(f, "    - Computation: {total_computation:?}")?;
            writeln!(f, "    - I/O: {total_io:.2?}")?;
            writeln!(f, "      - Send: {total_send:.2?}")?;
            writeln!(f, "      - Recv: {total_recv:.2?}")?;
            writeln!(f, "In particular:")?;
            writeln!(f, "  - Setup: {:.2?}", self.setup)?;

            for (i, round) in self.rounds.iter().enumerate() {
                writeln!(
                    f,
                    "  - Round {}: {:.2?}",
                    i + 1,
                    round.computation + round.sending + round.receiving
                )?;
                writeln!(f, "    - Computation: {:.2?}", round.computation)?;
                writeln!(f, "    - I/O: {:.2?}", round.sending + round.receiving)?;
                writeln!(f, "      - Send: {:.2?}", round.sending)?;
                writeln!(f, "      - Recv: {:.2?}", round.receiving)?;
            }
        } else {
            writeln!(f, "Protocol Performance:")?;
            writeln!(f, "  - Protocol took {total_computation:.2?} to complete")?;
            writeln!(f, "In particular:")?;
            writeln!(f, "  - Setup: {:.2?}", self.setup)?;
            Self::fmt_stages(f, self.setup, &self.setup_stages)?;

            for (i, round) in self.rounds.iter().enumerate() {
                if let Some(round_name) = round.round_name {
                    writeln!(f, "  - {round_name}: {:.2?}", round.computation)?
                } else {
                    writeln!(f, "  - Round {}: {:.2?}", i + 1, round.computation)?
                }
                Self::fmt_stages(f, round.computation, &round.stages)?;
            }
        }

        Ok(())
    }
}

impl PerfReport {
    fn fmt_stages(
        f: &mut fmt::Formatter,
        total: Duration,
        stages: &[StageDuration],
    ) -> fmt::Result {
        for stage in stages {
            let percent = stage.duration.as_secs_f64() / total.as_secs_f64() * 100.;
            writeln!(
                f,
                "    - {}: {:.2?} ({percent:.1}%)",
                stage.name, stage.duration
            )?;
        }
        if !stages.is_empty() {
            let stages_total = stages.iter().map(|s| s.duration).sum::<Duration>();
            let unstaged = total - stages_total;
            let percent = unstaged.as_secs_f64() / total.as_secs_f64() * 100.;
            writeln!(f, "    - Unstaged: {unstaged:.2?} ({percent:.1}%)")?;
        }
        Ok(())
    }
}
