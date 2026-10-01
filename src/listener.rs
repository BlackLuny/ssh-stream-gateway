//! Wait for a configured interface address without widening the listening scope.
use std::{future::Future, io, net::SocketAddr, time::Duration};
use tokio::{
    net::TcpListener,
    time::{Instant, sleep},
};
use tokio_util::sync::CancellationToken;

const FIRST_DELAY: Duration = Duration::from_secs(1);
const MAX_DELAY: Duration = Duration::from_secs(30);
const LOG_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct Waiting {
    attempt: u64,
    elapsed: Duration,
    next_delay: Duration,
}

/// Only EADDRNOTAVAIL is transient here: a WireGuard interface may not exist yet.
/// Port conflicts, invalid arguments and permissions require an operator fix.
/// Cancellation returns None and never creates a fallback listener.
pub(crate) async fn bind(
    address: SocketAddr,
    shutdown: &CancellationToken,
) -> io::Result<Option<TcpListener>> {
    retry(address, shutdown, TcpListener::bind, |waiting| {
        eprintln!(
            "Configured listener address {address} is not ready; waiting for interface (attempt {}, elapsed {}s, retry in {}s)",
            waiting.attempt,
            waiting.elapsed.as_secs(),
            waiting.next_delay.as_secs()
        );
    }).await
}

async fn retry<T, F, Fut, N>(
    address: SocketAddr,
    shutdown: &CancellationToken,
    mut bind: F,
    mut notify: N,
) -> io::Result<Option<T>>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<T>>,
    N: FnMut(Waiting),
{
    let started = Instant::now();
    let mut last_log = None;
    let mut attempt = 0u64;
    let mut delay = FIRST_DELAY;
    loop {
        attempt = attempt.saturating_add(1);
        let result = tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Ok(None),
            result = async { bind(address).await } => result,
        };
        match result {
            Ok(listener) => return Ok(Some(listener)),
            Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => {
                let now = Instant::now();
                if last_log.is_none_or(|previous| now.duration_since(previous) >= LOG_INTERVAL) {
                    notify(Waiting {
                        attempt,
                        elapsed: now.duration_since(started),
                        next_delay: delay,
                    });
                    last_log = Some(now);
                }
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => return Ok(None),
                    _ = sleep(delay) => {},
                }
                delay = delay.saturating_mul(2).min(MAX_DELAY);
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test(start_paused = true)]
    async fn late_address_retries_exact_destination_with_capped_backoff_and_sparse_logs() {
        let address: SocketAddr = "10.0.0.1:8443".parse().unwrap();
        let started = Instant::now();
        let mut attempted = Vec::new();
        let mut logged = Vec::new();
        let result = retry(
            address,
            &CancellationToken::new(),
            |given| {
                attempted.push((given, Instant::now().duration_since(started)));
                let result = if attempted.len() == 10 {
                    Ok("ready")
                } else {
                    Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
                };
                std::future::ready(result)
            },
            |waiting| logged.push(waiting),
        )
        .await
        .unwrap();
        assert_eq!(result, Some("ready"));
        assert!(attempted.iter().all(|(given, _)| *given == address));
        let seconds: Vec<_> = attempted
            .iter()
            .map(|(_, elapsed)| elapsed.as_secs())
            .collect();
        assert_eq!(seconds, [0, 1, 3, 7, 15, 31, 61, 91, 121, 151]);
        assert_eq!(
            logged
                .iter()
                .map(|w| w.elapsed.as_secs())
                .collect::<Vec<_>>(),
            [0, 61, 121]
        );
        assert_eq!(logged[0].attempt, 1);
        assert_eq!(logged[0].next_delay, FIRST_DELAY);
        assert_eq!(logged.last().unwrap().next_delay, MAX_DELAY);
    }

    #[tokio::test(start_paused = true)]
    async fn simulated_late_interface_eventually_opens_real_loopback_listener() {
        let held = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = held.local_addr().unwrap();
        drop(held);
        let mut attempts = 0;
        let listener = retry(
            address,
            &CancellationToken::new(),
            |given| {
                assert_eq!(given, address);
                attempts += 1;
                let ready = attempts == 3;
                async move {
                    if ready {
                        TcpListener::bind(given).await
                    } else {
                        Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
                    }
                }
            },
            |_| {},
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(attempts, 3);
        assert_eq!(listener.local_addr().unwrap(), address);
    }

    #[tokio::test(start_paused = true)]
    async fn occupied_port_and_nontransient_errors_fail_without_retry() {
        for kind in [
            io::ErrorKind::AddrInUse,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::Other,
        ] {
            let mut attempts = 0;
            let error = retry::<(), _, _, _>(
                "127.0.0.1:8443".parse().unwrap(),
                &CancellationToken::new(),
                |_| {
                    attempts += 1;
                    std::future::ready(Err(io::Error::from(kind)))
                },
                |_| panic!("permanent errors must not enter retry logging"),
            )
            .await
            .unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(attempts, 1);
        }
        let held = TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(
            bind(held.local_addr().unwrap(), &CancellationToken::new())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::AddrInUse
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_interrupts_backoff_without_an_extra_attempt() {
        let shutdown = CancellationToken::new();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let token = shutdown.clone();
        let task = tokio::spawn(async move {
            retry::<(), _, _, _>(
                "127.0.0.1:8443".parse().unwrap(),
                &token,
                |_| {
                    seen.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Err(io::Error::from(io::ErrorKind::AddrNotAvailable)))
                },
                |_| {},
            )
            .await
        });
        tokio::task::yield_now().await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        shutdown.cancel();
        assert!(task.await.unwrap().unwrap().is_none());
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn already_cancelled_shutdown_never_attempts_bind() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let result = retry::<(), _, _, _>(
            "127.0.0.1:8443".parse().unwrap(),
            &shutdown,
            |_| {
                panic!("cancelled startup must not bind");
                #[allow(unreachable_code)]
                std::future::ready(Ok(()))
            },
            |_| panic!("must not log"),
        )
        .await
        .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn cancellation_interrupts_a_pending_bind_future() {
        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let task = tokio::spawn(async move {
            retry::<(), _, _, _>(
                "127.0.0.1:8443".parse().unwrap(),
                &token,
                |_| std::future::pending(),
                |_| {},
            )
            .await
        });
        tokio::task::yield_now().await;
        shutdown.cancel();
        assert!(task.await.unwrap().unwrap().is_none());
    }
}
