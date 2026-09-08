use std::time::{Duration, Instant};

const SAMPLE_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Default)]
pub struct AvailableMemorySampler {
    last_sample: Option<Instant>,
    cached_bytes: Option<u64>,
}

impl AvailableMemorySampler {
    #[must_use]
    pub fn sample(&mut self) -> Option<u64> {
        let now = Instant::now();
        if self
            .last_sample
            .is_some_and(|last| now.duration_since(last) < SAMPLE_INTERVAL)
        {
            return self.cached_bytes;
        }

        let sample = platform_available_memory_bytes();
        self.last_sample = Some(now);
        self.cached_bytes = sample;
        sample
    }
}

#[derive(Debug, Default)]
pub struct ServoMemoryReportScheduler {
    last_request: Option<Instant>,
}

impl ServoMemoryReportScheduler {
    #[must_use]
    pub fn should_request(&mut self) -> bool {
        let now = Instant::now();
        if self
            .last_request
            .is_some_and(|last| now.duration_since(last) < SAMPLE_INTERVAL)
        {
            return false;
        }
        self.last_request = Some(now);
        true
    }
}

#[cfg(target_os = "linux")]
fn platform_available_memory_bytes() -> Option<u64> {
    let contents = std::fs::read_to_string("/proc/meminfo").ok()?;
    contents.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() != "MemAvailable" {
            return None;
        }
        let kilobytes = value.split_whitespace().next()?.parse::<u64>().ok()?;
        Some(kilobytes.saturating_mul(1024))
    })
}

#[cfg(target_os = "macos")]
fn platform_available_memory_bytes() -> Option<u64> {
    let output = std::process::Command::new("/usr/bin/vm_stat")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let output = String::from_utf8(output.stdout).ok()?;
    let page_size = output.lines().find_map(parse_page_size)?;
    let available_pages = output
        .lines()
        .filter_map(parse_memory_stat)
        .filter(|(label, _)| {
            matches!(
                *label,
                "Pages free" | "Pages inactive" | "Pages speculative"
            )
        })
        .map(|(_, pages)| pages)
        .sum::<u64>();
    Some(available_pages.saturating_mul(page_size))
}

#[cfg(target_os = "macos")]
fn parse_page_size(line: &str) -> Option<u64> {
    let prefix = "page size of ";
    let value = line.strip_prefix("Mach Virtual Memory Statistics: (")?;
    let value = value.strip_prefix(prefix)?;
    let value = value.strip_suffix(" bytes)")?;
    value.parse().ok()
}

#[cfg(target_os = "macos")]
fn parse_memory_stat(line: &str) -> Option<(&str, u64)> {
    let (label, value) = line.split_once(':')?;
    let value = value.trim().strip_suffix('.')?.parse().ok()?;
    Some((label, value))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn platform_available_memory_bytes() -> Option<u64> {
    None
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn platform_available_memory_bytes() -> Option<u64> {
    use std::mem::size_of;
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    status.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    let success = unsafe { GlobalMemoryStatusEx(&mut status) };
    (success != 0).then_some(status.ullAvailPhys)
}

#[cfg(test)]
mod tests {
    use super::{AvailableMemorySampler, ServoMemoryReportScheduler};

    #[test]
    fn test_sampler_starts_without_cached_memory() {
        let mut sampler = AvailableMemorySampler::default();

        let _ = sampler.sample();
        assert!(
            sampler.sample().is_some() || cfg!(not(any(target_os = "linux", target_os = "macos")))
        );
    }

    #[test]
    fn test_servo_memory_reports_are_throttled() {
        let mut scheduler = ServoMemoryReportScheduler::default();

        assert!(scheduler.should_request());
        assert!(!scheduler.should_request());
    }
}
