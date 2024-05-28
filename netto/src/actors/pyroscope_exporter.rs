use std::{time::{Duration, UNIX_EPOCH}, collections::HashMap};
use actix::{Actor, Context, AsyncContext, Handler};
use tokio::sync::mpsc::Sender;
use super::{FoldedStackTraceBatch, StackTrace, FoldedStackTraces};

pub struct PyroscopeExporter {
    endpoint: String,
    run_period: Duration,
    error_catcher_sender: Sender<anyhow::Error>,
    folded_traces: HashMap<StackTrace, usize>,
    async_runtime_handle: tokio::runtime::Handle,
    http_client: reqwest::Client,
    last_invocation_unix_time: u64,
    sample_rate: u64,
    application_name: String
}

impl PyroscopeExporter {
    pub fn new(
        endpoint: String,
        run_period: Duration,
        error_catcher_sender: Sender<anyhow::Error>,
        async_runtime: tokio::runtime::Handle,
        sample_rate: u64,
        num_possible_cpus: u64
    ) -> anyhow::Result<Self> {
        // Used to distinguish individual instances in a multi-host deployment
        let netto_host = std::env::var("NETTO_HOST");

        // Embed tags into the application name
        let application_name = String::from("netto") + &if let Ok(host) = netto_host {
            format!("{{host={host}}}")
        } else {
            String::new()
        };

        Ok(Self {
            endpoint,
            run_period,
            error_catcher_sender,
            folded_traces: HashMap::new(),
            async_runtime_handle: async_runtime,
            http_client: reqwest::Client::new(),
            last_invocation_unix_time: UNIX_EPOCH.elapsed()?.as_secs(),
            sample_rate: sample_rate * num_possible_cpus,
            application_name
        })
    }
    
    fn run_interval(&mut self) -> anyhow::Result<()> {
        // Convert the traces db into the textual "folded" format for compatibility with the Pyroscope server
        let body = self.folded_traces.iter()
            .map(|(trace, instances)| trace.frames
                .iter()
                .copied()
                .rev()
                .collect::<Vec<&str>>()
                .join(";") + &format!(" {instances}")
            )
            .collect::<Vec<String>>()
            .join("\n");

        // Clone various variables to send to the asynchronous Tokio task
        let client = self.http_client.clone();
        let endpoint = self.endpoint.clone();
        let from = self.last_invocation_unix_time;
        let until: u64 = UNIX_EPOCH.elapsed().unwrap().as_secs();
        self.last_invocation_unix_time = until;
        let sample_rate = self.sample_rate;
        let application_name = self.application_name.clone();

        self.async_runtime_handle.spawn(async move {
            if let Err(e) = client.post(endpoint + "/ingest")
                .query(&[
                    ("name", application_name.as_str()),
                    ("spyName", "netto"),
                    ("from", &format!("{}", from)),
                    ("until", &format!("{}", until)),
                    ("sampleRate", &format!("{}", sample_rate))
                ])
                .body(body)
                .send()
                .await {
                    eprintln!("Error sending data to pyroscope server: {e}");
                }
        });

        // Clear current traces db
        self.folded_traces.clear();
        
        Ok(())
    }
}

impl Handler<FoldedStackTraceBatch> for PyroscopeExporter {
    type Result = ();

    fn handle(&mut self, msg: FoldedStackTraceBatch, _ctx: &mut Self::Context) -> Self::Result {
        merge_folded_traces(&mut self.folded_traces, msg.traces);
    }
}

impl Actor for PyroscopeExporter {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.run_interval(self.run_period, |act, _| {
            if let Err(e) = act.run_interval() {
                act.error_catcher_sender.blocking_send(e).unwrap();
            }
        });
    }
}

fn merge_folded_traces(a: &mut FoldedStackTraces, b: FoldedStackTraces) {
    for (trace, instances) in b {
        *a.entry(trace).or_insert(0) += instances;
    }
}
