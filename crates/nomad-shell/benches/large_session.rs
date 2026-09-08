use std::hint::black_box;
use std::time::Instant;

use nomad_core::{BackendAvailability, Switches};
use nomad_engine::{
    BrowserRuntime, NavigationRequest, PageRenderer, RenderError, TabActivity, TabId,
};
use nomad_shell::{SessionBookmark, SessionSnapshot, SessionTab, ShellState};

const TAB_COUNTS: [usize; 6] = [10, 25, 50, 100, 250, 500];
const MEBIBYTE: u64 = 1024 * 1024;

#[derive(Default)]
struct BenchmarkRenderer;

impl PageRenderer for BenchmarkRenderer {
    fn load(&mut self, _request: &NavigationRequest) -> Result<(), RenderError> {
        Ok(())
    }
}

fn snapshot(tab_count: usize) -> SessionSnapshot {
    let tabs = (0..tab_count)
        .map(|index| SessionTab {
            url: Some(format!("https://example{index}.test/article/{index}")),
            pinned: index < 8,
            keep_alive: index < 4,
            user_priority: 0,
            workspace_id: Some((index % 8) as u64),
            container_id: Some((index % 4) as u64),
        })
        .collect();
    SessionSnapshot::new(
        tab_count.saturating_sub(1),
        tabs,
        vec![SessionBookmark {
            url: "https://example.test".to_owned(),
            title: "Example".to_owned(),
            folder: None,
        }],
    )
}

fn runtime_with_tabs(tab_count: usize) -> ShellState {
    let runtime = BrowserRuntime::new(Switches::default(), BackendAvailability::all_available())
        .expect("benchmark runtime");
    let mut shell = ShellState::new(runtime);
    for index in 1..tab_count {
        let tab_id = shell.new_tab();
        shell
            .set_tab_memory_estimate(tab_id, (32 + (index % 7) as u64 * 8) * MEBIBYTE)
            .expect("tab memory estimate");
        if index % 17 == 0 {
            shell
                .set_tab_activity(
                    tab_id,
                    TabActivity {
                        playing_audio: true,
                        ..TabActivity::default()
                    },
                )
                .expect("tab activity");
        }
    }
    shell
}

fn run_case(tab_count: usize) {
    let session = snapshot(tab_count);
    let encode_started = Instant::now();
    let encoded = session.to_json().expect("session serialization");
    let decoded = SessionSnapshot::from_json(&encoded).expect("session restoration");
    let encode_restore_ms = encode_started.elapsed().as_secs_f64() * 1_000.0;
    assert_eq!(decoded.tabs.len(), tab_count);

    let mut shell = runtime_with_tabs(tab_count);
    assert_eq!(shell.tabs().len(), tab_count);
    shell.observe_memory(512 * MEBIBYTE);
    let mut renderer = BenchmarkRenderer;

    let reclaim_started = Instant::now();
    let suspended = shell
        .reclaim_memory_with_renderer(&mut renderer)
        .expect("memory reclamation");
    let reclaim_ms = reclaim_started.elapsed().as_secs_f64() * 1_000.0;
    let diagnostics = shell.memory_diagnostics();

    let switch_target = shell.tabs().first().map_or(TabId::new(1), |tab| tab.id);
    let switch_started = Instant::now();
    shell
        .select_tab_with_renderer(switch_target, &mut renderer)
        .expect("tab switch");
    let switch_ms = switch_started.elapsed().as_secs_f64() * 1_000.0;

    let new_tab_started = Instant::now();
    let new_tab = shell.new_tab();
    black_box(new_tab);
    let new_tab_ms = new_tab_started.elapsed().as_secs_f64() * 1_000.0;

    black_box(decoded);
    println!(
        "large-session tabs={tab_count} session_bytes={} encode_restore_ms={encode_restore_ms:.3} \
         reclaim_ms={reclaim_ms:.3} suspended={} active={} warm={} sleeping={} \
         suspended_tabs={} browser_bytes={} tab_switch_ms={switch_ms:.3} new_tab_ms={new_tab_ms:.3}",
        encoded.len(),
        suspended.len(),
        diagnostics.active_tabs,
        diagnostics.warm_tabs,
        diagnostics.sleeping_tabs,
        diagnostics.suspended_tabs,
        diagnostics.browser_bytes,
    );
}

fn main() {
    for tab_count in TAB_COUNTS {
        run_case(tab_count);
    }
}
